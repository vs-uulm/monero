#include "mcrctSigs.h"
#include "ringct/rctOps.h"
#include <iostream>
#include <ringct/rctSigs.h>
#include "misc_log_ex.h"
#include "common/perf_timer.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


using namespace rct;
using namespace std;

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace mcrct {

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
        const size_t inputs = rv.mixRing[0].size();
        const size_t outputs = rv.ecdhInfo.size();
        key prehash;

        // FAILS : outputs=rv.ecdhInfo.size() is 2*rv.outPk.size() ...
        CHECK_AND_ASSERT_THROW_MES(const_cast<mcrctSig&>(rv).serialize_mcrctsig_base(ba, inputs, outputs),
                                   "Failed to serialize mcrctSigBase");
        cryptonote::get_blob_hash(ss.str(), h);
        hashes.push_back(hash2rct(h));

        keyV kv;
        if (rv.type == RCTTypeSimpleBulletproof || rv.type == RCTTypeFullBulletproof)
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

    mcrctSig genMCRct(const key &message, const mcctkeyV & inSk, const std::vector<xmr_amount> & amounts_in, const std::vector<key> & Colors_in, const keyV & destinations,
                    const std::vector<xmr_amount> & amounts, const std::vector<key> & Colors,
                    const mcctkeyM &mixRing, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout,
                    unsigned int index, mcctkeyV &outSk, bool bulletproof, hw::device &hwdev)
        {
        // should do same sanity checks as genRct

        mcrctSig rv;
        rv.type = RCTTypeFull;
        rv.message = message;
        rv.outPk.resize(destinations.size());

        mcctkeyV tmpSk;
        tmpSk.resize(inSk.size());
        rv.tmpPk.resize(inSk.size());
        // Create commitments to same colors as inputs
        for (size_t i=0; i<tmpSk.size(); i++) {
            skpkGen(tmpSk[i].color, rv.tmpPk[i].color); // generate cG of color blinding
            addKeys(rv.tmpPk[i].color, rv.tmpPk[i].color, Colors_in[i]); // add F to create Color commitment C = F + cG
        }

        // range sigs and ecdh amount exchange needed for BOTH amount und color -> double the size
        rv.p.rangeSigs.resize(destinations.size());
        //TODO: look at prunable colorSig

        keyM colorInc;
        colorInc.resize(destinations.size());
        keyV colorSk;
        colorSk.resize(destinations.size());
        std::vector<size_t> indices;
        indices.resize(destinations.size());

        //rv.p.colorSig.s1.resize(destinations.size());
        rv.ecdhInfo.resize(2*destinations.size());
        for (size_t i=0; i<destinations.size(); i++) {
            // rv.outPk[i].mask & .color is set by proveRange
            rv.outPk[i].dest = copy(destinations[i]);

            // generate blinding factors for F color commitments
            skpkGen(outSk[i].color, rv.outPk[i].color);
            addKeys(rv.outPk[i].color, rv.outPk[i].color, Colors[i]);

            // range signatures
            // amount @ 2*i
            rv.p.rangeSigs[i] = proveColoredRange(rv.outPk[i].mask, outSk[i].mask, amounts[i], rv.outPk[i].color);

            // call proveRange for .color as well, because it changes it!
            //TODO: ColorInclusionProof

            colorInc[i].resize(tmpSk.size());
            bool found=false;
            for(size_t inp = 0; inp < tmpSk.size(); inp++){
                subKeys(colorInc[i][inp],rv.outPk[i].color,rv.tmpPk[inp].color);
                if(equalKeys(Colors[i],Colors_in[inp]))
                {
                    found = true;
                    sc_sub(colorSk[i].bytes, outSk[i].color.bytes,tmpSk[inp].color.bytes);
                    indices[i] = inp;
                }
            }
            /*if(!found)
            {
                indices[i] = 0;
                skGen(colorSk[i]);
            }*/
            CHECK_AND_ASSERT_THROW_MES(found, "Invalid output color");

            // amount/color blinding factors encrypted to reciever
            // amount @ 2*i
            rv.ecdhInfo[2*i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[2*i].amount = d2h(amounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[2*i], amount_keys[i]);
            // color @ 2*i+1
            rv.ecdhInfo[2*i+1].mask = copy(outSk[i].color);
            rv.ecdhInfo[2*i+1].amount = Colors[i];
            hwdev.ecdhEncode(rv.ecdhInfo[2*i+1], amount_keys[i]);
        }

        rv.p.colorSig = genColBorromean(colorSk,colorInc,indices);

        //set txn fee
        if (amounts.size() > destinations.size())
            rv.txnFee = amounts[destinations.size()];
        else
            rv.txnFee = 0;

        key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
        //std::cout << prenative;
        key Native = hashToPoint(scalarmultBase(prenative));
        key txnFeeKey = scalarmultKey(Native, d2h(rv.txnFee));

        //std::cout << txnFeeKey;

        rv.mixRing = mixRing;
        rv.p.MGs.push_back(proveMCRctMG(
            get_mc_pre_mlsag_hash(rv, hwdev) ,
            rv.mixRing, inSk, amounts_in, outSk, amounts, rv.outPk, tmpSk, rv.tmpPk, kLRki, NULL, index, txnFeeKey, hwdev
        ));

        return rv;
    }


    bool verMCRct(const mcrctSig & rv, bool semantics) {
        //CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.colorsOutEqual.size(), true, "Too few colorsOutEqual signatures!");
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeFull, true, "VerCRct only supports RCTTypeFull signatures.");

        key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
        key Native = hashToPoint(scalarmultBase(prenative));
        key txnFeeKey = scalarmultKey(Native,d2h(rv.txnFee));

        // test rangeproofs
        for (size_t i = 0; i < rv.outPk.size(); i++) {
            bool result = verColoredRange(rv.outPk[i].mask, rv.p.rangeSigs[i], rv.outPk[i].color);
            if (!result) {
                LOG_PRINT_L1("Range proof verified failed for output " << i);
                return false;
            }
        }

        // TODO: verify color conservation
        keyM colorInc;
        colorInc.resize(rv.outPk.size());

        for (size_t i = 0; i < rv.outPk.size(); i++) {
            colorInc[i].resize(rv.tmpPk.size());
            for(size_t inp = 0; inp < rv.tmpPk.size(); inp++){
                subKeys(colorInc[i][inp],rv.outPk[i].color,rv.tmpPk[inp].color);
            }
        }
        bool result = verifyColBorromean(rv.p.colorSig, colorInc);
        if (!result) {
            LOG_PRINT_L1("Color conserving proof verified failed");
            return false;
        }


        bool mgVerd = verMCRctMG(
                rv.p.MGs[0], rv.mixRing, rv.tmpPk,  rv.outPk, txnFeeKey,
                get_mc_pre_mlsag_hash(rv, hw::get_device("default"))
        );

        return mgVerd;
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

    mgSig proveMCRctMG(
            const key &message, const mcctkeyM & pubs,
            const mcctkeyV & inSk,
            const std::vector<xmr_amount> & amounts_in,
            const mcctkeyV &outSk,
            const std::vector<xmr_amount> & amounts_out,
            const mcctkeyV & outPk,
            const mcctkeyV & tmpSk,
            const mcctkeyV & tmpPk,
            const multisig_kLRki *kLRki, key *mscout, unsigned int index,
            key txnFeeKey, hw::device &hwdev
    ) {
        mgSig mg;
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
            CHECK_AND_ASSERT_THROW_MES(pubs[i].size() == rows, "pubs is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(inSk.size() == rows, "Bad inSk size");
        CHECK_AND_ASSERT_THROW_MES(outSk.size() == outPk.size(), "Bad outSk/outPk size");
        CHECK_AND_ASSERT_THROW_MES((kLRki && mscout) || (!kLRki && !mscout), "Only one of kLRki/mscout is present");

        keyV sk(2*rows + 1);
        keyV tmp(2*rows + 1);

        size_t i = 0, j = 0;
        //TODO: maybe error in init here for last colequal
        for (i = 0; i < 2*rows+1; i++) {
            sc_0(sk[i].bytes);
            identity(tmp[i]);
        }
        keyM M(cols, tmp);
        //create the matrix to mg sig
        for (i = 0; i < cols; i++) {
            M[i][rows] = identity();
            for (j = 0; j < rows; j++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add input commitments in last row
            }
        }
        sc_0(sk[rows].bytes);
        for (j = 0; j < rows; j++) {
            sk[j] = copy(inSk[j].dest);
            sc_add(sk[rows].bytes, sk[rows].bytes, inSk[j].mask.bytes); //add masks vc+a, with amount v, color blind c and amount blind a in last row
            //key tmp;
            //sc_mul(tmp.bytes, inSk[j].color.bytes, d2h(amounts_in[i]).bytes);
            sc_muladd(sk[rows].bytes, d2h(amounts_in[j]).bytes, inSk[j].color.bytes, sk[rows].bytes); // add vc to the above (2 parts)
        }
        for (i = 0; i < cols; i++) {
            for (size_t j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }
        for (size_t j = 0; j < outPk.size(); j++) {
            sc_sub(sk[rows].bytes, sk[rows].bytes, outSk[j].mask.bytes); //subtract output masks in last row..
            sc_mulsub(sk[rows].bytes, d2h(amounts_out[j]).bytes, outSk[j].color.bytes , sk[rows].bytes);
        }

        // handle colors
        // private keys
        for (j = rows+1; j < 2*rows+1; j++) {
            auto k = j-rows-1;
            sc_sub(sk[j].bytes, inSk[k].color.bytes, tmpSk[k].color.bytes);     // F_i - T_i
            // nach \ref{ringct} nicht mehr nötig: sc_add(sk[j].bytes, sk[j].bytes, inSk[k].dest.bytes);               // + P_in
        }
        // public key matrix
        for (i = 0; i < cols; i++) {
            for (j = rows+1; j < 2*rows+1; j++) {
                auto k = j-rows-1;
                subKeys(M[i][j], pubs[i][k].color, tmpPk[k].color);             // F_in - F_out^0
                // nach \ref{ringct} nicht mehr nötig: addKeys(M[i][j], M[i][j], pubs[i][k].dest);                     // + P_in
            }
        }

        return MLSAG_Gen(message, M, sk, kLRki, mscout, index, rows, hwdev);
    }


    bool verMCRctMG(const mgSig &mg, const mcctkeyM & pubs, const mcctkeyV & tmpPk, const mcctkeyV & outPk, key txnFeeKey, const key &message) {
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
            CHECK_AND_ASSERT_MES(pubs[i].size() == rows, false, "pubs is not rectangular");
        }

        keyV tmp(2*rows + 1);
        size_t i = 0, j = 0;

        for (i = 0; i < 2*rows+1; i++) {
            identity(tmp[i]);
        }
        keyM M(cols, tmp);

        //create the matrix to mg sig
        for (j = 0; j < rows; j++) {
            for (i = 0; i < cols; i++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add Ci in last row
            }
        }
        for (i = 0; i < cols; i++) {
            for (j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }

        // handle colors
        // public key matrix
        for (i = 0; i < cols; i++) {
            for (j = rows+1; j < 2*rows+1; j++) {
                auto k = j-rows-1;
                subKeys(M[i][j], pubs[i][k].color, tmpPk[k].color);             // F_in - F_out^0
                // nach \ref{ringct} nicht mehr nötig: addKeys(M[i][j], M[i][j], pubs[i][k].dest);                     // + P_in
            }
        }

        if (MLSAG_Ver(message, M, mg, rows)) {
            return true;
        } else {
            std::cerr << "verCRctMG invalid MLSAG" << std::endl;
            return false;
        }
    }
}

