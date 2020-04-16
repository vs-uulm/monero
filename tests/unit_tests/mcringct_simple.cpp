/**
 * Authors: Ulm University, Institute for Distributed Systems
 * Lukas Müller, Michael Steck, Felix Engelmann
 */
#include "gtest/gtest.h"
#include <iostream>

#include "mcringct/mcrctTypes.h"
#include "mcringct/mcrctSigs.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"

#include <chrono>

using namespace mcrct;
using namespace rct;
using namespace std;
using namespace crypto;

TEST(mcringct_simple, mcringct_simple_types_Test){
    mcctkey test_mcctkey;
    test_mcctkey.dest = Z;
    test_mcctkey.mask = I;
    test_mcctkey.color = L;
    ASSERT_EQ(test_mcctkey.dest, Z);
    ASSERT_EQ(test_mcctkey.mask, I);
    ASSERT_EQ(test_mcctkey.color, L);
}

key hashToPoint(const key & hh) {
    key pointk;
    ge_p3 res;
    hash_to_p3(res, hh);
    ge_p3_tobytes(pointk.bytes, &res);
    return pointk;
}

static tuple<mcctkeyV, mcctkeyM, mcctkeyV, mcctkeyV> generate_test_transaction_keys(
        const vector<xmr_amount> &amounts_in, const vector<key> &colors_in,
        const unsigned int num_decoys, const vector<unsigned int> &index,
        const vector<xmr_amount> &amounts_out, vector<key> colors_out){

    mcctkeyV inSk(amounts_in.size());

    mcctkeyV rows(num_decoys + 1);
    mcctkeyM mixRing(inSk.size(), rows);
    for (size_t i = 0; i < mixRing.size(); i++) {
        for (size_t j = 0; j < mixRing[i].size(); j++) {
            mcctkey sk, pk;
            tie(sk, pk) = mcctskpkGen(amounts_in[i], colors_in[i]);
            mixRing[i][j] = pk;
            if (j == index[i]) {
                inSk[i] = sk;
            }
        }
    }

    mcctkeyV outSk(amounts_out.size());
    mcctkeyV outPk(amounts_out.size());
    for (size_t i = 0; i < outSk.size(); i++) {
        mcctkey sk, pk;
        tie(sk, pk) = mcctskpkGen(amounts_out[i], colors_out[i]);
        outSk[i] = sk;
        outPk[i] = pk;
    }

    return make_tuple(inSk, mixRing, outSk, outPk);
}

static tuple<mcctkey, mcctkeyV> generate_test_transaction_keys_simple(
        const xmr_amount amount_in, const key color_in,
        const unsigned int num_decoy, const unsigned int index){

    mcctkey inSk;
    mcctkeyV mixRing(num_decoy + 1);

    for (size_t i = 0; i < mixRing.size(); i++) {
        mcctkey sk, pk;
        tie(sk, pk) = mcctskpkGen(amount_in, color_in);
        mixRing[i] = pk;
        if (i == index) {
            inSk = sk;
        }
    }

    return make_tuple(inSk, mixRing);
}

TEST(mcringtct_simple, proveMCRctMGSimple){
    mcctkey inSk;
    mcctkeyV mixRing;

    key pregreen = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,9};
    key green = hashToPoint(scalarmultBase(pregreen));

    unsigned int index = 1;
    xmr_amount amount_in = 2;
    key color_in = green;

    mcctkey tmpSk;
    mcctkey tmpPk;

    tie(tmpSk, tmpPk) = mcctskpkGen(amount_in, color_in);

    tie(inSk, mixRing) =
            generate_test_transaction_keys_simple(amount_in, color_in, 10, index);

    key msg = skGen();

    auto time_before = chrono::high_resolution_clock::now();

    mgSig sig = proveMCRctMGSimple(msg, mixRing, inSk, amount_in, tmpSk, tmpPk,
            NULL, NULL, index, hw::get_device("default"));

    auto time_after = chrono::high_resolution_clock::now();
    cerr << "mcrct::proveMCRctMGSimple "
              << chrono::duration_cast<chrono::microseconds>(time_after - time_before).count() << " micros" << endl;

    time_before = chrono::high_resolution_clock::now();
    auto res = verMCRctMGSimple(sig, mixRing, tmpPk, msg);
    time_after = chrono::high_resolution_clock::now();
    cerr << "mcrct::verMCRctMGSimple " << chrono::duration_cast<chrono::microseconds>(time_after - time_before).count()
         << "micros " << endl;

    ASSERT_TRUE(res);
}

TEST(mcringtct_simple, proveEqual) {
    xmr_amount am = 5;
    key pregreen = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,9};
    key green = hashToPoint(scalarmultBase(pregreen));

    mcctkey colSk;
    mcctkey colPk;
    tie(colSk, colPk) = mcctskpkGen(am, green);

    ctkey pedSk, pedPk;
    tie(pedSk, pedPk) = ctskpkGen(am);

    equalSig s = proveEqual(colPk, pedPk, am, colSk, pedSk);

    bool res = verifyEqual(s, colPk, pedPk);
    ASSERT_TRUE(res);
}

TEST(mcringtct_simple, proveConservation) {
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key preRed = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,10};
    key red = hashToPoint(scalarmultBase(preRed));
    key preGreen = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9};
    key green = hashToPoint(scalarmultBase(preGreen));

    vector<unsigned int> index = {2, 0, 1};

    vector<xmr_amount> amounts_in({1, 2, 3});
    vector<key> colors_in;
    colors_in.push_back(red);
    colors_in.push_back(green);
    colors_in.push_back(red);

    vector<xmr_amount> amounts_out({2, 4});
    vector<key> colors_out;
    colors_out.push_back(green);
    colors_out.push_back(red);

    mcctkeyV tmpSk;
    mcctkeyV tmpPk;
    tmpSk.resize(amounts_in.size());
    tmpPk.resize(amounts_in.size());
    for (size_t i = 0; i < tmpSk.size(); i++) {
        tie(tmpSk[i], tmpPk[i]) = mcctskpkGen(amounts_in[i], colors_in[i]);
    }

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in, 10, index, amounts_out, colors_out
    );

    key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    key native = hashToPoint(scalarmultBase(preNative));
    key txnZeroFeeKey = scalarmultKey(native, d2h(0));

    key v_pk = identity();
    key r = identity();

    auto time_before = chrono::high_resolution_clock::now();

    tie(v_pk, r) = proveConservation(outPk, outSk, amounts_in, amounts_out, tmpPk, tmpSk, txnZeroFeeKey);

    auto time_after = chrono::high_resolution_clock::now();
    cerr << "mcrct::proveConservation " << chrono::duration_cast<chrono::microseconds>(time_after-time_before).count()
            << " micros" << endl;


    time_before = chrono::high_resolution_clock::now();

    bool res = verifyConservation(outPk, tmpPk, v_pk, r, txnZeroFeeKey);

    time_after = chrono::high_resolution_clock::now();
    cerr << "mcrct::verifyConservation " << chrono::duration_cast<chrono::microseconds>(time_after-time_before).count()
         << " micros" << endl;

    ASSERT_TRUE(res);
}

TEST(mcringtct_simple, verConservation) {
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key preRed = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,10};
    key red = hashToPoint(scalarmultBase(preRed));
    key preGreen = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9};
    key green = hashToPoint(scalarmultBase(preGreen));

    vector<unsigned int> index = {2, 0, 1};

    vector<xmr_amount> amounts_in({1, 2, 3});
    vector<key> colors_in;
    colors_in.push_back(red);
    colors_in.push_back(green);
    colors_in.push_back(red);

    // input and output amounts are _not_ matching
    vector<xmr_amount> amounts_out({2, 5});
    vector<key> colors_out;
    colors_out.push_back(green);
    colors_out.push_back(red);

    mcctkeyV tmpSk;
    mcctkeyV tmpPk;
    tmpSk.resize(amounts_in.size());
    tmpPk.resize(amounts_in.size());
    for (size_t i = 0; i < tmpSk.size(); i++) {
        tie(tmpSk[i], tmpPk[i]) = mcctskpkGen(amounts_in[i], colors_in[i]);
    }

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in, 10, index, amounts_out, colors_out
    );

    key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    key native = hashToPoint(scalarmultBase(preNative));
    key txnZeroFeeKey = scalarmultKey(native, d2h(0));

    key v_pk = identity();
    key r = identity();


    tie(v_pk, r) = proveConservation(outPk, outSk, amounts_in, amounts_out, tmpPk, tmpSk, txnZeroFeeKey);

    bool res = verifyConservation(outPk, tmpPk, v_pk, r, txnZeroFeeKey);

    ASSERT_FALSE(res);
}

static keyV to_dest_keyV(mcctkeyV mcctkeys){
    keyV tmp;
    for (mcctkey key: mcctkeys) {
        tmp.push_back(key.dest);
    }
    return tmp;
}

TEST(mcringct_simple, genMCRctSimple){
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    key native = hashToPoint(scalarmultBase(preNative));

    key preGreen = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9};
    key green = hashToPoint(scalarmultBase(preGreen));

    key notGreen;
    subKeys(notGreen, green, green);
    subKeys(notGreen, notGreen, green);

    /*
    vector<xmr_amount> amounts_in({2});
    vector<key> colors_in;
    colors_in.push_back(green);

    vector<xmr_amount> amounts_out({2});
    vector<key> colors_out;
    colors_out.push_back(green);
    */

    vector<xmr_amount> amounts_in({1, 2, 3});
    vector<key> colors_in;
    colors_in.push_back(native);
    colors_in.push_back(native);
    colors_in.push_back(green);

    vector<xmr_amount> amounts_out({1, 2, 3});
    vector<key> colors_out;
    colors_out.push_back(green);
    colors_out.push_back(green);
    colors_out.push_back(native);

    vector<unsigned int> index;
    index.resize(amounts_in.size());
    for (size_t i = 0; i < index.size(); i++) {
        // TODO: should use different indexes; irrelevant for testing
        index[i] = 1;
    }

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(amounts_in, colors_in, 10,
                                                                      index, amounts_out, colors_out);

    key msg = skGen();
    keyV destinations = to_dest_keyV(outPk);
    keyV amount_keys = to_dest_keyV(outSk);

    auto time_before = chrono::high_resolution_clock::now();

    auto mcrctsig = genMCRctSimple(msg, inSk, destinations, amounts_in, colors_in, amounts_out, colors_out,
                                   mixRing, amount_keys, NULL, NULL, index, outSk, true,
                                   hw::get_device("default"));

    auto time_after = chrono::high_resolution_clock::now();
    std::cerr << "mcrct::genMCRctSimple " << chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count()
    << " micros" << std::endl;

    time_before = chrono::high_resolution_clock::now();
    bool res = verMCRctSimple(mcrctsig, false);
    time_after = chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verMCRctSimple " << chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count()
             << " micros" << std::endl;

    ASSERT_TRUE(res);
}
TEST(mcringct_simple, genMCRctSimpleTime){
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key preNative = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    key native = hashToPoint(scalarmultBase(preNative));

    key preGreen = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 9};
    key green = hashToPoint(scalarmultBase(preGreen));

    for(int noin=1; noin<19; noin++) {
        for (int noout = 1; noout < 19; noout++) {

            vector<xmr_amount> amounts_in;
            vector<key> colors_in;

            amounts_in.resize(noin);
            int allin = 0;
            for(int i =0; i< noin; i++){
                amounts_in[i]=i+100;
                allin += i+100;
                colors_in.push_back(green);
                // cout << "in " << i << " : " << amounts_in[i] << endl;
            }

            vector<xmr_amount> amounts_out;
            vector<key> colors_out;
            amounts_out.resize(noout);
            int allout = 0;
            for(int i = 0; i < (noout-1); i++){
                amounts_out[i]=1;
                allout += 1;
                colors_out.push_back(green);
                // cout << "out " << i << " : " << amounts_out[i] << endl;
            }
            amounts_out[noout-1] = allin-allout;
            colors_out.push_back(green);

            vector<unsigned int> index;
            index.resize(amounts_in.size());
            for (size_t i = 0; i < index.size(); i++) {
                // TODO: should use different indexes; irrelevant for testing
                index[i] = 1;
            }

            // edit here to specify times to run generation and verification
            int iterations = 30;

            auto time_gen_max = 0;
            auto time_gen_min = std::numeric_limits<unsigned long>::max();
            auto time_gen_total = 0;
            auto time_ver_max = 0;
            auto time_ver_min = std::numeric_limits<unsigned long>::max();
            auto time_ver_total = 0;

            for (int i = 0; i < iterations; i++) {

                tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(amounts_in, colors_in, 10,
                                                                                  index, amounts_out, colors_out);

                key msg = skGen();
                keyV destinations = to_dest_keyV(outPk);
                keyV amount_keys = to_dest_keyV(outSk);

                auto time_before_gen = chrono::high_resolution_clock::now();
                auto mcrctsig = genMCRctSimple(msg, inSk, destinations, amounts_in, colors_in, amounts_out, colors_out,
                                               mixRing, amount_keys, NULL, NULL, index, outSk, true,
                                               hw::get_device("default"));
                auto time_after_gen = chrono::high_resolution_clock::now();
                auto diff_gen = chrono::duration_cast<std::chrono::microseconds>(
                        time_after_gen - time_before_gen).count();
                time_gen_max = time_gen_max < diff_gen ? diff_gen : time_gen_max;
                time_gen_min = time_gen_min > diff_gen ? diff_gen : time_gen_min;
                time_gen_total += diff_gen;


                auto time_before_ver = chrono::high_resolution_clock::now();
                bool res = verMCRctSimple(mcrctsig, false);
                if (!res) cerr << "Failed to verify";
                auto time_after_ver = chrono::high_resolution_clock::now();
                auto diff_ver = chrono::duration_cast<std::chrono::microseconds>(
                        time_after_ver - time_before_ver).count();
                time_ver_max = time_ver_max < diff_ver ? diff_ver : time_ver_max;
                time_ver_min = time_ver_min > diff_ver ? diff_ver : time_ver_min;
                time_ver_total += diff_ver;

                cout << "in: " << noin << " out: " << noout << " gen: " << diff_gen << " ver: " << diff_ver << endl;
            }
        }
    }

}
static tuple<ctkeyV, ctkeyM, ctkeyV, ctkeyV> generate_test_rct_transaction_keys (
        const std::vector<xmr_amount> amounts_in,
        const unsigned int num_decoys, const std::vector<unsigned int> &index,
        const std::vector<xmr_amount> amounts_out
) {
    //ASSERT_EQ(amounts_in.size(), colors_in.size());
    //ASSERT_EQ(amounts_out.size(), colors_out.size());
    ctkeyV inSk(amounts_in.size());

    ctkeyV rows(num_decoys + 1);
    ctkeyM mixRingT(inSk.size(), rows);
    for (size_t i = 0; i < mixRingT.size(); i++) {
        for (size_t j = 0; j < mixRingT[i].size(); j++) {
            ctkey sk, pk;
            tie(sk, pk) = ctskpkGen(amounts_in[i]);
            mixRingT[i][j] = pk;
            if (j == index[i]) {
                inSk[i] = sk;
            }
        }
    }

    ctkeyV outSk(amounts_out.size());
    ctkeyV outPk(amounts_out.size());
    for (unsigned int i=0; i<outSk.size(); i++) {
        ctkey sk, pk;
        tie(sk, pk) = ctskpkGen(amounts_out[i]);
        outSk[i] = sk;
        outPk[i] = pk;
    }

    return make_tuple(inSk, mixRingT, outSk, outPk);
}

static keyV to_rct_dest_keyV(ctkeyV _ctkeys) {
    keyV tmp;
    for (auto _ctkey: _ctkeys) {
        tmp.push_back(_ctkey.dest);
    }
    return tmp;
}

TEST(mcringct_simple, genRctSimple){
    ctkeyV inSk, outSk, outPk;
    ctkeyM mixRing;


    for(int noin=1; noin<19; noin++) {
        for(int noout=1; noout<19; noout++) {

            vector<xmr_amount> amounts_in;
            amounts_in.resize(noin);
            int allin = 0;
            for(int i =0; i< noin; i++){
                amounts_in[i]=i+100;
                allin += i+100;
                // cout << "in " << i << " : " << amounts_in[i] << endl;
            }

            vector<xmr_amount> amounts_out;
            amounts_out.resize(noout);
            int allout = 0;
            for(int i = 0; i < (noout-1); i++){
                amounts_out[i]=1;
                allout += 1;
                // cout << "out " << i << " : " << amounts_out[i] << endl;
            }
            amounts_out[noout-1] = allin-allout;
            // cout << "out " << noout-1 << " : " << amounts_out[noout-1] << endl;

            vector<unsigned int> index;
            index.resize(amounts_in.size());
            for (size_t i = 0; i < index.size(); i++) {
                // TODO: should use different indexes; irrelevant for testing
                index[i] = 1;
            }
            // edit here to specify times to run generation and verification
            int iterations = 30;

            auto time_gen_max = 0;
            auto time_gen_min = std::numeric_limits<unsigned long>::max();
            auto time_gen_total = 0;
            auto time_ver_max = 0;
            auto time_ver_min = std::numeric_limits<unsigned long>::max();
            auto time_ver_total = 0;

            for (int i = 0; i < iterations; i++) {

                tie(inSk, mixRing, outSk, outPk) = generate_test_rct_transaction_keys(amounts_in, 10,
                                                                                      index, amounts_out);

                key msg = skGen();
                keyV destinations = to_rct_dest_keyV(outPk);
                keyV amount_keys = to_rct_dest_keyV(outSk);

                RCTConfig rct_config;
                //rct_config.range_proof_type = RangeProofBorromean;
                rct_config.range_proof_type = RangeProofMultiOutputBulletproof;

                auto time_before_gen = chrono::high_resolution_clock::now();
                rctSig sig = genRctSimple(msg, inSk, destinations, amounts_in, amounts_out, 0, mixRing, amount_keys,
                                          NULL, NULL, index, outSk, rct_config, hw::get_device("default"));
                //msg, inSk, destinations, amounts_in, amounts_out, 0, mixRing, amount_keys,
                //NULL, NULL, index, outSk, false, hw::get_device("default"));
                auto time_after_gen = chrono::high_resolution_clock::now();
                auto diff_gen = chrono::duration_cast<std::chrono::microseconds>(
                        time_after_gen - time_before_gen).count();
                time_gen_max = time_gen_max < diff_gen ? diff_gen : time_gen_max;
                time_gen_min = time_gen_min > diff_gen ? diff_gen : time_gen_min;
                time_gen_total += diff_gen;


                auto time_before_ver = chrono::high_resolution_clock::now();
                bool res = verRctSimple(sig);
                if (!res) std::cerr << "Failed to verify" << std::endl;
                auto time_after_ver = chrono::high_resolution_clock::now();
                auto diff_ver = chrono::duration_cast<std::chrono::microseconds>(
                        time_after_ver - time_before_ver).count();
                time_ver_max = time_ver_max < diff_ver ? diff_ver : time_ver_max;
                time_ver_min = time_ver_min > diff_ver ? diff_ver : time_ver_min;
                time_ver_total += diff_ver;

                cout << "in: " << noin << " out: " << noout << " gen: " << diff_gen << " ver: " << diff_ver << endl;
            }
        }
    }
}
