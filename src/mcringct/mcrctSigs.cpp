/**
 * Authors: Ulm University, Institute for Distributed Systems
 * Lukas Müller, Michael Steck, Felix Engelmann
 */
#include "mcrctSigs.h"
#include "ringct/rctOps.h"
#include <iostream>
#include <ringct/rctSigs.h>
#include <common/threadpool.h>
#include "misc_log_ex.h"
#include "common/perf_timer.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


using namespace rct;
using namespace std;

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace mcrct {
    /**
     * Checks if the RCTType is simple
     * @param type - type of the RCT
     * @return <i>true</i> if the RCTType is simple, otherwise <i>false</i>
     */
    bool is_simple(int type){
        switch (type) {
            case RCTTypeSimple:
            case RCTTypeBulletproof:
            case RCTTypeBulletproof2:
                return true;
            default:
                return false;
        }
    }

    tuple<mcctkey, mcctkey> mcctskpkGen(xmr_amount amount, key F) {
        mcctkey sk, pk;

        // generate private/public address key
        skpkGen(sk.dest, pk.dest);
        // generate private a, public aG in V=vC+aG
        skpkGen(sk.mask, pk.mask);
        // generate private b, public bG in C=F+bG
        skpkGen(sk.color, pk.color);

        // create C=F+bG
        addKeys(pk.color, pk.color, F);

        // add vC with v=amount to aG to get public C=vC+aG, for amount
        key am = d2h(amount);
        key vC = scalarmultKey(pk.color, am);
        addKeys(pk.mask, pk.mask, vC);

        return make_tuple(sk, pk);
    }

    key get_mc_pre_mlsag_hash(const mcrctSig &rv, hw::device &hwdev)
    {
        keyV hashes;
        hashes.reserve(3);
        hashes.push_back(rv.message);
        crypto::hash h;

        std::stringstream ss;
        binary_archive<true> ba(ss);
        CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
        //const size_t inputs = is_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
        const size_t inputs = is_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
        const size_t outputs = rv.ecdhInfo.size();
        key prehash;

        // FAILS : outputs=rv.ecdhInfo.size() is 2*rv.outPk.size() ...
        CHECK_AND_ASSERT_THROW_MES(const_cast<mcrctSig&>(rv).serialize_mcrctsig_base(ba, inputs, outputs),
                                   "Failed to serialize mcrctSigBase");
        cryptonote::get_blob_hash(ss.str(), h);
        hashes.push_back(hash2rct(h));

        keyV kv;
        if (rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2)
        {
            kv.reserve((6*2+9) * rv.p.bulletproofs.size());
            for (const auto &p: rv.p.bulletproofs)
            {
                // V are not hashed as they're expanded from outPk.mask
                // (and thus hashed as part of rctSigBase above)
                kv.push_back(p.A);
                kv.push_back(p.S);
                kv.push_back(p.T1);
                kv.push_back(p.T2);
                kv.push_back(p.taux);
                kv.push_back(p.mu);
                for (size_t n = 0; n < p.L.size(); ++n)
                    kv.push_back(p.L[n]);
                for (size_t n = 0; n < p.R.size(); ++n)
                    kv.push_back(p.R[n]);
                kv.push_back(p.a);
                kv.push_back(p.b);
                kv.push_back(p.t);
            }
        }
        else
        {
            kv.reserve((64*3+1) * rv.p.rangeSigs.size());
            for (const auto &r: rv.p.rangeSigs)
            {
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.asig.s0[n]);
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.asig.s1[n]);
                kv.push_back(r.asig.ee);
                for (size_t n = 0; n < 64; ++n)
                    kv.push_back(r.Ci[n]);
            }
        }
        hashes.push_back(cn_fast_hash(kv));
        hwdev.mlsag_prehash(ss.str(), inputs, outputs, hashes, mcctV2ctV(rv.outPk), prehash);
        return  prehash;
    }

    colorSig genColBorromean(const keyV & x, const keyM & P, const std::vector<size_t> & indices) {
        keyV alpha;
        alpha.resize(P.size());
        keyV cm; //last c per row
        cm.resize(P.size());
        colorSig bb;
        bb.r.resize(P.size());

        // 1
        for (size_t ii = 0 ; ii < P.size() ; ii++) {
            bb.r[ii].resize(P[ii].size());
            skGen(alpha[ii]); // generate random alpha_i

            if (indices[ii] != P[ii].size() - 1) // not for last element
            {
                key ci1;
                key alphaG = scalarmultBase(alpha[ii]);
                ci1 = hash_to_scalar(alphaG); // 1b seed loop
                for (size_t i = indices[ii] + 1; i < P[ii].size() - 1; i++) {
                    skGen(bb.r[ii][i]); // random number
                    key rGcK;
                    addKeys2(rGcK, bb.r[ii][i], ci1, P[ii][i]);
                    ci1 = hash_to_scalar(rGcK);
                }
                cm[ii] = copy(ci1);
            }
        }
        // 2
        key connector = d2h(1);
        for (size_t ii = 0 ; ii < P.size() ; ii++) {
            skGen(bb.r[ii][P[ii].size() - 1]); // random r_i,m
            key last;
            if (indices[ii] == P[ii].size() - 1) {
                last = scalarmultBase(alpha[ii]);
            } else {
                addKeys2(last, bb.r[ii][P[ii].size() - 1], cm[ii], P[ii][P[ii].size() - 1]); // last = rG+cK
            }
            connector = hash_to_scalar(scalarmultKey(last,connector));
        }
        bb.c1 = connector; // c1 = hash

        for (size_t ii = 0 ; ii < P.size() ; ii++) {
            key clast = copy(bb.c1); // reference ci,1 to c1
            if (indices[ii] != 0){
                for (size_t i = 0; i < indices[ii]; i++) {
                    skGen(bb.r[ii][i]); // random number
                    key rGcK;
                    addKeys2(rGcK, bb.r[ii][i], clast, P[ii][i]);
                    clast = hash_to_scalar(rGcK);
                }
            }
            // tie loop
            //alpha[ii]
            sc_mulsub(bb.r[ii][indices[ii]].bytes, clast.bytes, x[ii].bytes , alpha[ii].bytes);
        }
        return bb;
    }

    bool verifyColBorromean(colorSig bb, const keyM & P){
        keyV L; //last c per row
        L.resize(P.size());

        for (size_t ii = 0; ii < P.size(); ii++){
            key c=copy(bb.c1);
            for (size_t j=0; j < P[ii].size();j++){
                addKeys2(L[ii],bb.r[ii][j],c,P[ii][j]);
                c=hash_to_scalar(L[ii]);
            }
        }
        key connector = d2h(1);
        for (size_t ii = 0; ii < P.size(); ii++) {
            connector = hash_to_scalar(scalarmultKey(L[ii],connector));
        }

        return equalKeys(connector, bb.c1);
    }

    /**
     * A function proving that the outputs are equal to the temporary commitments
     * and transitively to the inputs.
     *
     * @param outPk - public commitments of the output
     * @param outSk - private keys / blinding factors of the output
     * @param amounts_in - amounts of input
     * @param amounts_out - amounts of output
     * @param tmpPk - public temporary commitment to the inputs
     * @param tmpSk - private temporary keys / blinding factors of the temporary commitments
     * @return a tuple of a Schnorr style signature
     */
    tuple<key, key> proveConservation(
            const mcctkeyV &outPk,
            const mcctkeyV & outSk,
            const std::vector<xmr_amount> & amounts_in,
            const std::vector<xmr_amount> & amounts_out,
            const mcctkeyV & tmpPk,
            const mcctkeyV & tmpSk,
            key txnFeeKey
            ){
        key commit_2_zero;
        identity(commit_2_zero);

        // sum of T_V^j
        for (size_t i = 0; i < tmpPk.size(); i++) {
            addKeys(commit_2_zero, commit_2_zero, tmpPk[i].mask);
        }

        // subtract the sum of V_i from the sum above
        for (size_t i = 0; i < outPk.size(); i++) {
            subKeys(commit_2_zero, commit_2_zero, outPk[i].mask);
        }

        // subtract txnFee from the sum above
        subKeys(commit_2_zero, commit_2_zero, txnFeeKey);

        key sk_of_commit;
        zero(sk_of_commit);

        // sum (v^j * c_T^j) + a_T^j
        for (size_t i = 0; i < tmpPk.size(); i++) {
            // v*j * c_T^j
            sc_muladd(sk_of_commit.bytes, d2h(amounts_in[i]).bytes, tmpSk[i].color.bytes, sk_of_commit.bytes);
            // ... + a_T^j
            sc_add(sk_of_commit.bytes, sk_of_commit.bytes, tmpSk[i].mask.bytes);
        }

        // subtract the sum (v_i * c_i) + a_i from the sum above
        for (size_t i = 0; i < outPk.size(); i++) {
            // ... - (v_i * c_i)
            sc_mulsub(sk_of_commit.bytes, d2h(amounts_out[i]).bytes, outSk[i].color.bytes, sk_of_commit.bytes);
            // ... - a_i
            sc_sub(sk_of_commit.bytes, sk_of_commit.bytes, outSk[i].mask.bytes);
        }

        // Sign using a Schnorr style non-interactive signature over elliptic curve (see RFC 8235)
        // commit_2_zero corresponds to A
        // sk_of_commit corresponds to a

        key v_sk, v_pk;
        skpkGen(v_sk, v_pk);

        // create non-interactive challenge by creating a hash of concatenation of G,V and A
        // c = H(G || V || A)
        keyV concat_GVA;
        concat_GVA.reserve(3);

        //TODO: look for a nicer way to get the base point G

        // get the basepoint
        key identityScalar = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        key basePoint_G = scalarmultBase(identityScalar);

        concat_GVA.push_back(basePoint_G);
        concat_GVA.push_back(v_pk);
        concat_GVA.push_back(commit_2_zero);

        key c = hash_to_scalar(concat_GVA);

        key r;
        // r = v - a*c
        sc_mulsub(r.bytes, sk_of_commit.bytes, c.bytes, v_sk.bytes);

        return make_tuple(v_pk, r);
    }

    /**
     * A function to verify the given parameters of a Schnorr Style signature, which proves
     * that the given outputs are equal to the temporary commitments and transitively to the
     * inputs.
     *
     * @param outPk - public commitments to the output
     * @param tmpPk - public temporary commitments to the input
     * @param v_pk - public key of a schnorr style signature
     * @param r - schnorr style signature
     * @param txnFeeKey - taxation fee
     * @return <i>true</i> if the verification succeeds, <i>false</i> otherwise
     */
    bool verifyConservation(const mcctkeyV &outPk, const mcctkeyV &tmpPk, const key &v_pk, const key &r, key txnFeeKey){

        key commit_2_zero;
        identity(commit_2_zero);

        // sum of T_V^j
        for (size_t i = 0; i < tmpPk.size(); i++) {
            addKeys(commit_2_zero, commit_2_zero, tmpPk[i].mask);
        }

        // subtract the sum of V_i from the sum above
        for (size_t i = 0; i < outPk.size(); i++) {
            subKeys(commit_2_zero, commit_2_zero, outPk[i].mask);
        }

        // subtract txnFee from the sum above
        subKeys(commit_2_zero, commit_2_zero, txnFeeKey);

        // Verify using a Schnorr style non-interacitve signature over elliptic curve (see RFC 8235)
        // commit_2_zero corresponds to A

        // create non-interactive challenge by creating a hash of concatenation of G,V and A
        // c = H(G || V || A)
        keyV concat_GVA;
        concat_GVA.reserve(3);

        //TODO: look for a nicer way to get the base point G

        // get the basepoint
        key identityScalar = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        key basePoint_G = scalarmultBase(identityScalar);

        concat_GVA.push_back(basePoint_G);
        concat_GVA.push_back(v_pk);
        concat_GVA.push_back(commit_2_zero);

        key c = hash_to_scalar(concat_GVA);

        // V = rG + cA
        key gr = scalarmultBase(r);
        key v_pk_to_verify = addKeys(gr, scalarmultKey(commit_2_zero, c));

        if (!equalKeys(v_pk, v_pk_to_verify)) {
            LOG_PRINT_L1("verifyConservation: verify of conservation failed");
            return false;
        }

        return true;
    }



    /**
     * A function to verify the given Multi Colored Ring Confidential Transaction signature.
     * @param rv - the mcrct signature to verify
     * @param semantics
     * @return <i>true</i> if the verification succeeds, <i>false</i> otherwise
     */
    bool verMCRctSimple(const mcrctSig &rv, bool semantics){
        //TODO: try-catch ge_frombytes_vartime
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple, false, "verMCRctSimple called on non RCTTypeSimple rctSig");
        CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of rv.outPk / rv.p.rangeSigs");
        CHECK_AND_ASSERT_MES(rv.tmpPk.size() == rv.p.MGs.size(), false, "Mismatching sizes of rv.tmpPk / rv.p.MG");
        CHECK_AND_ASSERT_MES(rv.tmpPk.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.tmpPk / rv.mixRing");
        CHECK_AND_ASSERT_MES(rv.p.colorsOutEqual.size() == 1, false, "rv.p.colorsOutEqual's size is not 1");

        key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        ge_p3 res;
        key native;
        hash_to_p3(res, scalarmultBase(preNative));
        ge_p3_tobytes(native.bytes, &res);
        // key native = hash_to_p3(scalarmultBase(preNative));
        key txnFeeKey = scalarmultKey(native, d2h(rv.txnFee));

        // prepare a thread pool and a results queue
        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool &tpool = tools::threadpool::getInstance();
        tools::threadpool::waiter waiter;

        // Verify rangeproofs
        results.clear();
        results.resize(rv.outPk.size());
        for (size_t i = 0; i < rv.outPk.size(); i++) {
            // create a thread for each verColoredRange call
            tpool.submit(&waiter, [&, i]
            {
                results[i] = verColoredRange(rv.outPk[i].mask, rv.p.rangeSigs[i], rv.outPk[i].color);
            });
        }
        // wait for each verColoredRange call to finish
        waiter.wait(&tpool);
        // check results
        for (size_t i = 0; i < results.size(); i++) {
            if (!results[i]) {
                LOG_PRINT_L1("Colored range proof verified failed for output " << i);
                return false;
            }
        }

        // create matrix used to prove color
        keyM colorInc;
        colorInc.resize(rv.outPk.size());

        for (size_t i = 0; i < rv.outPk.size(); i++) {
            colorInc[i].resize(rv.tmpPk.size());
            for (size_t inp = 0; inp < rv.tmpPk.size(); inp++) {
                // T_C^inp - C_i
                subKeys(colorInc[i][inp], rv.tmpPk[inp].color, rv.outPk[i].color);
            }
        }

        bool result_colBor = verifyColBorromean(rv.p.colorSig, colorInc);
        if (!result_colBor) {
            LOG_PRINT_L1("Color conserving proof verified failed");
            return false;
        }

        bool result_conserv = verifyConservation(rv.outPk, rv.tmpPk, rv.p.colorsOutEqual[0].first,
                                                 rv.p.colorsOutEqual[0].second, txnFeeKey);
        if (!result_conserv) {
            LOG_PRINT_L1("Colored conservation proof verified failed");
            return false;
        }

        key full_message = get_mc_pre_mlsag_hash(rv, hw::get_device("default"));

        // clear results and resize to fit mixRing sizes
        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0; i < rv.mixRing.size(); i++) {
            // create a thread for each verMCRctMGSimple call
            tpool.submit(&waiter, [&, i]{
                results[i] = verMCRctMGSimple(rv.p.MGs[i], rv.mixRing[i], rv.tmpPk[i], full_message);
            });
        }
        // wait for each verMCRctMGSimple call to finish
        waiter.wait(&tpool);

        // check results
        for (size_t i = 0; i < results.size(); i++) {
            if (!results[i]) {
                LOG_PRINT_L1("verMCRctMGSimple failed for input " << i);
                return false;
            }
        }

        // all signatures could be verified
        return true;
    }

    //proveColoredRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveColoredRange(key & C, key & mask, const xmr_amount & amount, const key & Fct) {
        sc_0(mask.bytes);
        identity(C);
        bits b;
        d2b(b, amount);
        rangeSig sig;
        key64 ai;
        key64 CiH;
        int i = 0;
        key Hi = Fct;
        for (i = 0; i < ATOMS; i++) {
            skGen(ai[i]);
            if (b[i] == 0) {
                scalarmultBase(sig.Ci[i], ai[i]);
            }
            if (b[i] == 1) {
                addKeys1(sig.Ci[i], ai[i], Hi);
            }
            subKeys(CiH[i], sig.Ci[i], Hi);
            sc_add(mask.bytes, mask.bytes, ai[i].bytes);
            addKeys(C, C, sig.Ci[i]);

            Hi = addKeys(Hi, Hi);
        }
        sig.asig = genBorromean(ai, sig.Ci, CiH, b);
        return sig;
    }

    //see above.
    bool verifyBorromean(const boroSig &bb, const ge_p3 P1[64], const ge_p3 P2[64]) {
        key64 Lv1; key chash, LL;
        int ii = 0;
        ge_p2 p2;
        for (ii = 0 ; ii < 64 ; ii++) {
            // equivalent of: addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
            ge_double_scalarmult_base_vartime(&p2, bb.ee.bytes, &P1[ii], bb.s0[ii].bytes);
            ge_tobytes(LL.bytes, &p2);
            chash = hash_to_scalar(LL);
            // equivalent of: addKeys2(Lv1[ii], bb.s1[ii], chash, P2[ii]);
            ge_double_scalarmult_base_vartime(&p2, chash.bytes, &P2[ii], bb.s1[ii].bytes);
            ge_tobytes(Lv1[ii].bytes, &p2);
        }
        key eeComputed = hash_to_scalar(Lv1); //hash function fine
        return equalKeys(eeComputed, bb.ee);
    }

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    bool verColoredRange(const key & C, const rangeSig & as, const key & Fct) {
        try
        {
            PERF_TIMER(verRange);
            ge_p3 CiH[64], asCi[64];
            int i = 0;
            ge_p3 Ctmp_p3 = ge_p3_identity;
            key Hi = Fct;
            for (i = 0; i < 64; i++) {
                // faster equivalent of:
                // subKeys(CiH[i], as.Ci[i], H2[i]);
                // addKeys(Ctmp, Ctmp, as.Ci[i]);
                ge_cached cached;
                ge_p3 p3;
                ge_p1p1 p1;
                CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&p3, Hi.bytes) == 0, false, "point conv failed");
                ge_p3_to_cached(&cached, &p3);
                CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&asCi[i], as.Ci[i].bytes) == 0, false, "point conv failed");
                ge_sub(&p1, &asCi[i], &cached);
                ge_p3_to_cached(&cached, &asCi[i]);
                ge_p1p1_to_p3(&CiH[i], &p1);
                ge_add(&p1, &Ctmp_p3, &cached);
                ge_p1p1_to_p3(&Ctmp_p3, &p1);

                Hi = addKeys(Hi, Hi);
            }
            key Ctmp;
            ge_p3_tobytes(Ctmp.bytes, &Ctmp_p3);
            if (!equalKeys(C, Ctmp))
                return false;
            if (!verifyBorromean(as.asig, asCi, CiH))
                return false;
            return true;
        }
            // we can get deep throws from ge_frombytes_vartime if input isn't valid
        catch (...) { return false; }
    }

    /**
     * A function that creates a MLSAG Signature to prove the conservation of color
     * and value from the inputs to the temporary commitments.
     *
     * @param message - the messae to sign
     * @param pubs - vector with the decoy inputs
     * @param inSk - private keys / blinding factors of the input
     * @param amount_in - amounts of input
     * @param tmpSk - private keys / blinding factors of temporary commitments
     * @param tmpPk - public temporary commitments to the inputs
     * @param kLRki
     * @param mscout
     * @param index - index to the position of the real inputs in the decoy vector <i>pubs</i>
     * @param hwdev
     * @return a MLSAG Signature
     */
    mgSig proveMCRctMGSimple(const key &message,
            const mcctkeyV &pubs,
            const mcctkey &inSk,
            const xmr_amount &amount_in,
            const mcctkey &tmpSk,
            const mcctkey &tmpPk,
            const multisig_kLRki *kLRki, key *mscout, unsigned int index,
            hw::device &hwdev)
    {
        mgSig mg;

        CHECK_AND_ASSERT_THROW_MES(pubs.size() >=1, "Empty pubs");

        size_t cols = pubs.size();
        size_t rows = 1;

        keyV sk(3 * rows);
        keyV tmp(3 * rows);


        // init
        for (size_t i = 0; i < 3 * rows; i++) {
            sc_0(sk[i].bytes);
            identity(tmp[i]);
        }

        keyM M(cols, tmp);
        // create the matrix to mg sig
        for (size_t i = 0; i < cols; i++) {

            // fill first part of matrix with pub destinations (P)
            M[i][0] = pubs[i].dest;

            // fill second part of the matrix with the color commitments C minus temporary color commitments.
            // For each C, the difference to all temporary color commitments is calculated.
            // C^j_n - T^j_C
            subKeys(M[i][1], pubs[i].color, tmpPk.color);

            // fill third part of the matrix with the amount/value commitments V minus temporary amount/value commitments.
            // For each V, the difference to all temporary amount/value commitments is calculated.
            // V^j_n - T^j_V
            subKeys(M[i][2], pubs[i].mask, tmpPk.mask);
        }

        // create private keys vector

        // fill first part with secret keys
        // x^j
        sk[0] = inSk.dest;

        // fill second part with difference of color blinding c and temporary color blinding c_T
        // c^j-c^j_T
        sc_sub(sk[1].bytes, inSk.color.bytes, tmpSk.color.bytes);

        // fill third part of vector
        // (v^j * c^j) + a^j
        sc_muladd(sk[2].bytes, d2h(amount_in).bytes, inSk.color.bytes, inSk.mask.bytes);

        // subtract (v^j * c^j_T + a^j_T) from the above term
        sc_mulsub(sk[2].bytes, d2h(amount_in).bytes, tmpSk.color.bytes, sk[2].bytes);
        sc_sub(sk[2].bytes, sk[2].bytes, tmpSk.mask.bytes);


        return MLSAG_Gen(message, M, sk, kLRki, mscout, index, rows, hwdev);

    }

    /**
     * A function to check the validity of a given MLSAG signature.
     * @param mg - the MLSAG signature to verify
     * @param pubs- vector with decoy inputs
     * @param tmpPk - public temporary commitments to the input
     * @param message - the signed message
     * @return <i>true</i> if the verification succeeds, <i>false</i> otherwise
     */
    bool verMCRctMGSimple(const mgSig &mg, const mcctkeyV &pubs, const mcctkey &tmpPk, const key &message){
        CHECK_AND_ASSERT_MES(pubs.size() >= 1, false, "Empty pubs");

        size_t cols = pubs.size();
        size_t rows = 1;

        keyV tmp(3 * rows);

        // init
        for (size_t i = 0; i < 3 * rows; i++) {
            identity(tmp[i]);
        }

        //create the matrix to verify mg sig
        keyM M(cols, tmp);
        for (size_t i = 0; i < cols; i++) {

            //fill first part of the matrix with pub destinations (P)
            M[i][0] = pubs[i].dest;

            //fill second part of the matrix with the color commitments C minus temporary color commitments.
            // For each C, the difference to all temporary color commitments is calculated.
            // C^j_n - T^j_C
            subKeys(M[i][1], pubs[i].color, tmpPk.color);

            // fill third part of the matrix with the amount/value commitments V minus temporary amount/value commitments.
            // For each V, the difference to all temporary amount/value commitments is calculated.
            subKeys(M[i][2], pubs[i].mask, tmpPk.mask);
        }

        if (MLSAG_Ver(message, M, mg, rows)) {
            return true;
        } else {
            LOG_PRINT_L1("verMCRctMGSimple invalid MLSAG");
            return false;
        }
    }

    mcrctSig genMCRctSimple(const key &message,
                            const mcctkeyV &inSk,
                            const mcctkeyV &inPk,
                            const keyV &destinations,
                            const std::vector<xmr_amount> &amounts_in,
                            const std::vector<key> &colors_in,
                            const std::vector<xmr_amount> &amounts_out,
                            const std::vector<key> &colors_out,
                            const keyV &amount_keys,
                            const std::vector<multisig_kLRki> *kLRki,
                            multisig_out *msout,
                            xmr_amount txnFee,
                            unsigned int mixin,
                            hw::device &hwdev){

        //TODO: sanity checks

        // populate from blockchain
        // put inPk at random index and populate rest of the matrix with keys from the blockchain

        std::vector<unsigned int> index;
        index.resize(inPk.size());
        mcctkeyM mixRing(inPk.size());
        mcctkeyV outSk; //TODO: check if empty

        for (size_t i = 0; i < inPk.size(); i++) {
            mixRing[i].resize(mixin + 1);
            index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
        }

        return genMCRctSimple(message, inSk, destinations, amounts_in, colors_in, amounts_out, colors_out,
                mixRing, amount_keys, kLRki, msout, index, outSk, false, hwdev);

    }

    /**
     * A function generating a Multi Colored Ring Confidential Transaction Simple
     * Signature to prove the genuineness of it's input parameters
     *
     * @param message - the message to sign
     * @param inSk - private keys / blinding factors of the input
     * @param destinations - the public one time recipient keys
     * @param amounts_in - amounts of input
     * @param colors_in - colors of input
     * @param amounts_out - amounts of output
     * @param colors_out - colors of output
     * @param mixRing - matrix of input decoys
     * @param amount_keys - secret keys used for Diffie-Hellmann exchange
     * @param kLRki
     * @param msout
     * @param index - index to the position of the real inputs in the decoys matrix <i>mixRing</i>
     * @param outSk - private keys / blinding factors of the output
     * @param bulletproof
     * @param hwdev
     * @return a Multi Colored Ring Confidential Transaction Signature
     */
    //TODO: msout & kLRKi unused -> drop parameters?
    mcrctSig genMCRctSimple(const key &message,
                            const mcctkeyV &inSk,
                            const keyV &destinations,
                            const std::vector<xmr_amount> &amounts_in,
                            const std::vector<key> &colors_in,
                            const std::vector<xmr_amount> &amounts_out,
                            const std::vector<key> &colors_out,
                            const mcctkeyM &mixRing,
                            const keyV &amount_keys,
                            const std::vector<multisig_kLRki> *kLRki,
                            multisig_out *msout,
                            const std::vector<unsigned int> &index,
                            mcctkeyV &outSk,
                            bool bulletproof,
                            hw::device &hwdev){

        CHECK_AND_ASSERT_THROW_MES(amounts_in.size() > 0, "Empty amounts_in");
        CHECK_AND_ASSERT_THROW_MES(amounts_in.size() == inSk.size(), "Mismatched sizes of amounts_in / inSK");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Mismatched sizes of amount_keys / destinations");
        CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Mismatched sizes of mixRing / inSk");
        for (size_t n = 0; n < mixRing.size(); n++) {
            CHECK_AND_ASSERT_THROW_MES(mixRing[0].size() == mixRing[n].size(), "mixRing not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(index.size() == amounts_in.size(), "Mismatched sizes of index / amounts_in");

        mcrctSig rv;
        rv.type = RCTTypeSimple;
        rv.message = message;

        // set txn fee using the native color
        if (amounts_out.size() > destinations.size()) {
            rv.txnFee = amounts_out[destinations.size()];
        } else {
            rv.txnFee = 0;
        }

        key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        ge_p3 res;
        key native;
        hash_to_p3(res, scalarmultBase(preNative));
        ge_p3_tobytes(native.bytes, &res);
        key txnFeeKey = scalarmultKey(native, d2h(rv.txnFee));

        // prepare output sizes
        rv.outPk.resize(destinations.size());
        rv.tmpPk.resize(inSk.size());

        // create intermediate (tmp) commitments with same colors but different blinding factors
        mcctkeyV tmpSk;
        tmpSk.resize(inSk.size());

        for (size_t i = 0; i < tmpSk.size(); i++) {
            // T_C = F + cG
            skpkGen(tmpSk[i].color, rv.tmpPk[i].color);
            addKeys(rv.tmpPk[i].color, colors_in[i], rv.tmpPk[i].color);

            // T_V = v*T_C + aG
            skpkGen(tmpSk[i].mask, rv.tmpPk[i].mask);
            key vT_C;
            scalarmultKey(vT_C, rv.tmpPk[i].color, d2h(amounts_in[i]));
            addKeys(rv.tmpPk[i].mask, rv.tmpPk[i].mask, vT_C);
        }

        // create outputs

        // range sigs and ecdh need double the size due to the addition of colors
        rv.p.rangeSigs.resize(destinations.size());
        rv.ecdhInfo.resize(2 * destinations.size());
        rv.p.colorsOutEqual.resize(1); // single conservation prove


        // matrix and sk vector used for color prove
        keyM colorInc;
        colorInc.resize(destinations.size());
        keyV colorSk;
        colorSk.resize(destinations.size());
        std::vector<size_t> indices;
        indices.resize(destinations.size());
        // ----

        for (size_t i = 0; i < destinations.size(); i++) {
            // add destination
            rv.outPk[i].dest = copy(destinations[i]);

            // generate blinding factors for the F color commitments
            skpkGen(outSk[i].color, rv.outPk[i].color);
            // C = F + cG
            addKeys(rv.outPk[i].color, rv.outPk[i].color, colors_out[i]);

            // generate blinding factors for the V value/amount commitments
            skpkGen(outSk[i].mask, rv.outPk[i].mask);
            // V = vC + aG
            key vC = scalarmultKey(rv.outPk[i].color, d2h(amounts_out[i]));
            addKeys(rv.outPk[i].mask, rv.outPk[i].mask, vC);


            // range signatures
            rv.p.rangeSigs[i] = proveColoredRange(rv.outPk[i].mask, outSk[i].mask,
                    amounts_out[i], rv.outPk[i].color);

            // create matrix used for color proof
            colorInc[i].resize(tmpSk.size());
            for (size_t inp = 0; inp < tmpSk.size(); inp++) {

                // T_C^inp - C_i
                subKeys(colorInc[i][inp], rv.tmpPk[inp].color, rv.outPk[i].color);

                if (equalKeys(colors_out[i], colors_in[inp])) {
                    sc_sub(colorSk[i].bytes, tmpSk[inp].color.bytes, outSk[i].color.bytes);
                    indices[i] = inp;
                }
            }


            // amount/color blinding factors encrypted to receiver
            // amount @ 2*i
            rv.ecdhInfo[2 * i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[2 * i].amount = d2h(amounts_out[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[2 * i], amount_keys[i], false);
            // color @ 2*i+1
            rv.ecdhInfo[2 * i + 1].mask = copy(outSk[i].color);
            rv.ecdhInfo[2*i +1].amount = colors_out[i];
            hwdev.ecdhEncode(rv.ecdhInfo[2 * i + 1], amount_keys[i], false);
        }

        // proof of Color using matrix and vectors created above
        rv.p.colorSig = genColBorromean(colorSk, colorInc, indices);

        // prove conservation
        tie(rv.p.colorsOutEqual[0].first, rv.p.colorsOutEqual[0].second) =
                proveConservation(rv.outPk, outSk, amounts_in, amounts_out, rv.tmpPk, tmpSk, txnFeeKey);


        rv.p.MGs.resize(amounts_in.size());

        rv.mixRing = mixRing;

        key full_message = get_mc_pre_mlsag_hash(rv, hwdev);

        // create prove
        for (size_t i = 0; i < amounts_in.size(); i++) {
            rv.p.MGs[i] = proveMCRctMGSimple(full_message, rv.mixRing[i], inSk[i], amounts_in[i],
                    tmpSk[i], rv.tmpPk[i], (kLRki ? &(*kLRki)[i]: NULL),
                    (msout ? &msout->c[i] : NULL), index[i], hwdev);
        }

        return rv;
    }

    xmr_amount populateFromBlockchainSimple(mcctkeyV &mixRing, const mcctkey &inPk, unsigned int mixin){
        unsigned int index = randXmrAmount(mixin);

        for (size_t i = 0; i < mixin; i++) {
            if (i != index) {
                getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

    void getKeyFromBlockchain(mcctkey &a, size_t reference_index){
        a.mask = pkGen();
        a.dest = pkGen();
        a.color = pkGen();
    }
}
