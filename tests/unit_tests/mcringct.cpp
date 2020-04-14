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


TEST(mcringct, types) {
    mcctkey mcctkey_;
    mcctkey_.dest = Z;
    mcctkey_.mask = I;
    mcctkey_.color = L;
    ASSERT_EQ(mcctkey_.dest, Z);
    ASSERT_EQ(mcctkey_.mask, I);
    ASSERT_EQ(mcctkey_.color, L);
}

/*
TEST(colringct, gen) {

    key message = zero();
    cctkeyV inSk;
    cctkeyV inPk;
    keyV destinations;
    std::vector<xmr_amount> amounts;
    std::vector<xmr_amount> amounts_color;
    keyV amount_keys;
    multisig_kLRki *kLRki;
    multisig_out *msout;
    int mixin;
    //hw::device hwdev;

    genCRct(message, inSk, inPk, destinations, amounts, amounts_color, amount_keys, kLRki, msout, mixin, hwdev);
}
 */


static keyV to_dest_keyV(mcctkeyV _mcctkeys) {
    keyV tmp;
    for (auto _mcctkey: _mcctkeys) {
        tmp.push_back(_mcctkey.dest);
    }
    return tmp;
}

static keyV to_rct_dest_keyV(ctkeyV _ctkeys) {
    keyV tmp;
    for (auto _ctkey: _ctkeys) {
        tmp.push_back(_ctkey.dest);
    }
    return tmp;
}

static tuple<mcctkeyV, mcctkeyM, mcctkeyV, mcctkeyV> generate_test_transaction_keys (
        const std::vector<xmr_amount> amounts_in, const std::vector<key> colors_in,
        const unsigned int num_decoys, const unsigned int index,
        const std::vector<xmr_amount> amounts_out, std::vector<key> colors_out
) {
    //ASSERT_EQ(amounts_in.size(), colors_in.size());
    //ASSERT_EQ(amounts_out.size(), colors_out.size());

    mcctkeyV inSk(amounts_in.size());
    mcctkeyM mixRing(num_decoys+1, inSk);

    for (unsigned int i=0; i<mixRing.size(); i++) {
        for (unsigned int j=0; j<inSk.size(); j++) {
            mcctkey sk, pk;
            tie(sk, pk) = mcctskpkGen(amounts_in[j], colors_in[j]);
            mixRing[i][j] = pk;
            if (i==index) inSk[j] = sk;
        }
    }

    mcctkeyV outSk(amounts_out.size());
    mcctkeyV outPk(amounts_out.size());
    for (unsigned int i=0; i<outSk.size(); i++) {
        mcctkey sk, pk;
        tie(sk, pk) = mcctskpkGen(amounts_out[i], colors_out[i]);
        outSk[i] = sk;
        outPk[i] = pk;
    }

    return make_tuple(inSk, mixRing, outSk, outPk);
}

static tuple<ctkeyV, ctkeyM, ctkeyV, ctkeyV> generate_test_rct_transaction_keys (
        const std::vector<xmr_amount> amounts_in,
        const unsigned int num_decoys, const unsigned int index,
        const std::vector<xmr_amount> amounts_out
) {
    //ASSERT_EQ(amounts_in.size(), colors_in.size());
    //ASSERT_EQ(amounts_out.size(), colors_out.size());

    ctkeyV inSk(amounts_in.size());
    ctkeyM mixRing(num_decoys+1, inSk);

    for (unsigned int i=0; i<mixRing.size(); i++) {
        for (unsigned int j=0; j<inSk.size(); j++) {
            ctkey sk, pk;
            tie(sk, pk) = ctskpkGen(amounts_in[j]);
            mixRing[i][j] = pk;
            if (i==index) inSk[j] = sk;
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

    return make_tuple(inSk, mixRing, outSk, outPk);
}

TEST(mcringct, mcctskpkGen) {

    xmr_amount amount = 5;
    key color = pkGen();

    mcctkey sk_in, pk_in;

    tie(sk_in, pk_in) = mcctskpkGen(amount, color);
    auto time_before = std::chrono::high_resolution_clock::now();
    for(int i=1000; i<2000; i++) {
        auto bla = ctskpkGen(i);
    }
    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::mcctskpkGen " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;


    mcctkey sk_out, pk_out;
    tie(sk_out, pk_out) = mcctskpkGen(amount, color);

    // test if we know key for subtraction

    // C = F + aG
    // V = vC + bG = v F + v a G + b G = vF + (v a+b)G

    // V_in - V_out = 0F + ((v a_in + b_in) - (v a_out + b_out))G

    subKeys(pk_out.mask, pk_in.mask, pk_out.mask); // V_in - V_out
    // private key should be

    key sk;
    key tmp;
    sc_0(sk.bytes);
    sc_0(tmp.bytes);
    sc_mul(tmp.bytes, sk_in.color.bytes, d2h(amount).bytes); // tmp = v a_in
    sc_add(sk.bytes, sk_in.mask.bytes, tmp.bytes); // tmp + b_in

    sc_mul(tmp.bytes, sk_out.color.bytes, d2h(amount).bytes); // tmp = v a_out
    sc_sub(sk.bytes, sk.bytes, tmp.bytes); // - tmp
    sc_sub(sk.bytes, sk.bytes, sk_out.mask.bytes); // - b_out

    ASSERT_EQ(scalarmultBase(sk),pk_out.mask);
}

TEST(mcringct, mcctskpkGen_valuediff) {

    xmr_amount amount_in = 5;
    xmr_amount amount_out = 6;
    key color = pkGen();

    mcctkey sk_in, pk_in;
    tie(sk_in, pk_in) = mcctskpkGen(amount_in, color);

    mcctkey sk_out, pk_out;
    tie(sk_out, pk_out) = mcctskpkGen(amount_out, color);

    // test if we know key for subtraction

    // C = F + aG
    // V = vC + bG = v F + v a G + b G = vF + (v a+b)G

    // V_in - V_out = 0F + ((v a_in + b_in) - (v a_out + b_out))G

    subKeys(pk_out.mask, pk_in.mask, pk_out.mask); // V_in - V_out
    // private key should be

    key sk;
    key tmp;
    sc_0(sk.bytes);
    sc_0(tmp.bytes);
    sc_mul(tmp.bytes, sk_in.color.bytes, d2h(amount_in).bytes); // tmp = v a_in
    sc_add(sk.bytes, sk_in.mask.bytes, tmp.bytes); // tmp + b_in

    sc_mul(tmp.bytes, sk_out.color.bytes, d2h(amount_out).bytes); // tmp = v a_out
    sc_sub(sk.bytes, sk.bytes, tmp.bytes); // - tmp
    sc_sub(sk.bytes, sk.bytes, sk_out.mask.bytes); // - b_out

    ASSERT_FALSE(equalKeys(scalarmultBase(sk),pk_out.mask));
}

TEST(mcringct, mcctskpkGen_colordiff) {

    xmr_amount amount_in = 5;
    xmr_amount amount_out = 5;
    //key color_in = pkGen();
    //key color_out = pkGen();

    key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
    key Native = hashToPoint(scalarmultBase(prenative));

    key pregreen = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,9};
    key Green = hashToPoint(scalarmultBase(pregreen));
    key color_in = Native;
    key color_out = Green;

    //std::cout << color_in;
    //std::cout << color_inh;

    mcctkey sk_in, pk_in;
    tie(sk_in, pk_in) = mcctskpkGen(amount_in, color_in);

    mcctkey sk_out, pk_out;
    tie(sk_out, pk_out) = mcctskpkGen(amount_out, color_out);

    // test if we know key for subtraction

    // C = F + aG
    // V = vC + bG = v F + v a G + b G = vF + (v a+b)G

    // V_in - V_out = 0F + ((v a_in + b_in) - (v a_out + b_out))G

    subKeys(pk_out.mask, pk_in.mask, pk_out.mask); // V_in - V_out
    // private key should be

    key sk;
    key tmp;
    sc_0(sk.bytes);
    sc_0(tmp.bytes);
    sc_mul(tmp.bytes, sk_in.color.bytes, d2h(amount_in).bytes); // tmp = v a_in
    sc_add(sk.bytes, sk_in.mask.bytes, tmp.bytes); // tmp + b_in

    sc_mul(tmp.bytes, sk_out.color.bytes, d2h(amount_out).bytes); // tmp = v a_out
    sc_sub(sk.bytes, sk.bytes, tmp.bytes); // - tmp
    sc_sub(sk.bytes, sk.bytes, sk_out.mask.bytes); // - b_out

    ASSERT_FALSE(equalKeys(scalarmultBase(sk),pk_out.mask));
}

TEST(mcringct, genColBorromean) {
    keyV x(3);
    std::vector<size_t> indices({0,1,2});
    keyM P;
    P.resize(x.size());

    for(int i=0;i<x.size();i++){
        P[i].resize(3);
        for(int j=0;j < P[i].size();j++){
            key sk,pk;
            tie(sk,pk) = skpkGen();
            P[i][j]=pk;
            if(i==j){
                x[i]=sk;
            }
        }
    }

    auto time_before = std::chrono::high_resolution_clock::now();
    colorSig cs = genColBorromean(x,P,indices);
    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::genColBorromean " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    time_before = std::chrono::high_resolution_clock::now();
    auto res = verifyColBorromean(cs,P);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verifyColBorromean " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    ASSERT_TRUE(res);
}

TEST(mcringct, proveColoredRange) {


    key C, mask;
    xmr_amount amount = 1000;
    key Fct = pkGen();

    auto time_before = std::chrono::high_resolution_clock::now();
    rangeSig as = proveColoredRange(C, mask, amount, Fct);
    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::proveColoredRange " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    time_before = std::chrono::high_resolution_clock::now();
    auto res = verColoredRange(C, as, Fct);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verColoredRange " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    ASSERT_TRUE(res);
}

TEST(mcringct, proveRange) {


    key C, mask;
    xmr_amount amount = 1000;

    auto time_before = std::chrono::high_resolution_clock::now();
    rangeSig as = proveRange(C, mask, amount);
    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::proveRange " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    time_before = std::chrono::high_resolution_clock::now();
    auto res = verRange(C, as);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::verRange " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    ASSERT_TRUE(res);
}

TEST(mcringct, generate_test_transaction_keys) {
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    //key Red = hash2rct(crypto::cn_fast_hash("euro",4));
    key sk,Red;
    tie(sk,Red) = skpkGen();

    unsigned int index=1;
    vector<xmr_amount> amounts_in({1,2,3});
    vector<key> colors_in;
    colors_in.push_back(Red);
    colors_in.push_back(Red);
    colors_in.push_back(Red);
    vector<xmr_amount> amounts_out({6});
    vector<key> colors_out;
    colors_out.push_back(Red);

    ASSERT_EQ(amounts_out[0], 6);

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in,
            10, index,
            amounts_out, colors_out
    );

    ASSERT_GT(inSk.size(), 0);
    ASSERT_GT(mixRing.size(), 0);
    // check secret/publick correspondence for input
    /*for (size_t j=0; j<inSk.size(); j++) {
        // inSk.dest are secret keys for mixRing[index].dest
        ASSERT_EQ(scalarmultBase(inSk[j].dest), mixRing[index][j].dest);
        // inSk.mask are blinding factors x for mixRing[index].mask commitment C=xG+aH, with a=amount
        key xG = scalarmultBase(inSk[j].mask);
        key aH = scalarmultH(d2h(amounts_in[j]));
        ASSERT_EQ(addKeys(xG, aH), mixRing[index][j].mask);
        // inSk.color are blinding factors x for mixRing[index].color commitment C=xG+fH, with f=color
        //ASSERT_EQ(addKeys(scalarmultBase(inSk[j].color), scalarmultH(d2h(colors_in[j]))), mixRing[index][j].color);
    }

    ASSERT_GT(outSk.size(), 0);
    ASSERT_GT(outPk.size(), 0);
    // check secret/publick correspondence for output
    for (size_t j=0; j<outSk.size(); j++) {
        // inSk.dest are secret keys for mixRing[index].dest
        ASSERT_EQ(scalarmultBase(outSk[j].dest), outPk[j].dest);
        // inSk.mask are blinding factors x for mixRing[index].mask commitment C=xG+aH, with a=amount
        key xG = scalarmultBase(outSk[j].mask);
        key aH = scalarmultH(d2h(amounts_out[j]));
        ASSERT_EQ(addKeys(xG, aH), outPk[j].mask);
        // inSk.color are blinding factors x for mixRing[index].color commitment C=xG+fH, with f=color
        //ASSERT_EQ(addKeys(scalarmultBase(outSk[j].color), scalarmultH(d2h(colors_out[j]))), outPk[j].color);
    }*/
}

TEST(mcringct, proveMCRctMG) {
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key sk,Red;
    tie(sk,Red) = skpkGen();
    key NotRed;
    subKeys(NotRed, Red, Red);
    subKeys(NotRed, NotRed, Red);

    unsigned int index=1;
    vector<xmr_amount> amounts_in({1,2,3});
    vector<key> colors_in;
    colors_in.push_back(Red);
    colors_in.push_back(Red);
    colors_in.push_back(Red);
    vector<xmr_amount> amounts_out({6,20,20});
    vector<key> colors_out;
    colors_out.push_back(Red);
    colors_out.push_back(Red);
    colors_out.push_back(NotRed);

    mcctkeyV tmpSk;
    mcctkeyV tmpPk;
    tmpSk.resize(colors_in.size());
    tmpPk.resize(colors_in.size());
    for (size_t i=0; i<tmpSk.size(); i++) {
        skpkGen(tmpSk[i].color, tmpPk[i].color); // generate cG of color blinding
        addKeys(tmpPk[i].color, tmpPk[i].color, colors_in[i]); // add F to create Color commitment C = F + cG
    }

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in,
            10, index,
            amounts_out, colors_out
    );

    key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
    //std::cout << prenative;
    key Native = hashToPoint(scalarmultBase(prenative));
    key txnZeroFeeKey = scalarmultKey(Native, d2h(0));

    key msg = skGen();

    auto time_before = std::chrono::high_resolution_clock::now();

    mgSig sig = proveMCRctMG(
            msg, mixRing, inSk, amounts_in, outSk, amounts_out, outPk, tmpSk, tmpPk, NULL, NULL, index, txnZeroFeeKey, hw::get_device("default")
    );

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::proveMCRctMG " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    time_before = std::chrono::high_resolution_clock::now();
    auto res = verMCRctMG(sig, mixRing, tmpPk, outPk, txnZeroFeeKey, msg);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verMCRctMG " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;


    ASSERT_TRUE(res);
}

TEST(mcringct, MCRctSig_valid) {
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
    key Native = hashToPoint(scalarmultBase(prenative));

    key pregreen = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,9};
    key Green = hashToPoint(scalarmultBase(pregreen));

    key NotGreen;
    subKeys(NotGreen, Green, Green);
    subKeys(NotGreen, NotGreen, Green);

    unsigned int index=1;
    vector<xmr_amount> amounts_in({1,2,3});
    vector<key> colors_in;
    colors_in.push_back(Native);
    colors_in.push_back(Native);
    colors_in.push_back(Green);
    //vector<xmr_amount> amounts_out({1,2,3,30,30});
    vector<xmr_amount> amounts_out({1,2,3});
    vector<key> colors_out;
    colors_out.push_back(Green);
    colors_out.push_back(Green);
    colors_out.push_back(Native);
    //colors_out.push_back(Green);
    //colors_out.push_back(NotGreen);

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in,
            10, index,
            amounts_out, colors_out
    );

    key msg = skGen();  // random message

    #warning "parameter 'amount_keys' should be shared secret? yes, but for testing irrelevant"

    auto time_before = std::chrono::high_resolution_clock::now();

    auto mcrctsig = genMCRct(
            msg, inSk , amounts_in,  colors_in, to_dest_keyV(outPk), amounts_out, colors_out, mixRing, to_dest_keyV(outSk),
            NULL, NULL, index, outSk, false, hw::get_device("default")
    );

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::genMCRct " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    time_before = std::chrono::high_resolution_clock::now();
    bool result=verMCRct(mcrctsig, false);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verMCRct " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    ASSERT_TRUE(result);
}

TEST(mcringct, time_rct)
{
    //Ring CT Stuff
    //ct range proofs

    ctkeyV inSk, outSk, outPk;
    ctkeyM mixRing;

    vector<xmr_amount> amounts_in({1,2,3});
    vector<xmr_amount> amounts_out({1,2,3});

    unsigned int index=1;


    tie(inSk, mixRing, outSk, outPk) = generate_test_rct_transaction_keys(
            amounts_in,
            10, index,
            amounts_out
    );

    key msg = skGen();  // random message

    auto time_before = std::chrono::high_resolution_clock::now();

    rctSig s = genRct(msg, inSk, to_rct_dest_keyV(outPk), amounts_out, mixRing, to_rct_dest_keyV(outSk), NULL, NULL, index, outSk, false, hw::get_device("default"));

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::genRct " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    time_before = std::chrono::high_resolution_clock::now();
    bool result=rct::verRct(s);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::verRct " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;


    //verify rct data
    ASSERT_TRUE(result);
}

void test_mcrctsig(int inputs, int outputs){
    mcctkeyV inSk, outSk, outPk;
    mcctkeyM mixRing;

    key prenative = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
    key Native = hashToPoint(scalarmultBase(prenative));

    key pregreen = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,9};
    key Green = hashToPoint(scalarmultBase(pregreen));

    unsigned int index=1;
    vector<xmr_amount> amounts_in;
    vector<key> colors_in;
    int native = 0;
    for(int i=0; i<inputs-1; i++){
        amounts_in.push_back(42);
        native += 42;
        colors_in.push_back(Native);
    }
    amounts_in.push_back(31415);
    colors_in.push_back(Green);

    vector<xmr_amount> amounts_out;
    vector<key> colors_out;
    for(int i=0; i<outputs-2; i++){
        amounts_out.push_back(1);
        native -= 1;
        colors_out.push_back(Native);
    }
    amounts_out.push_back(native);
    colors_out.push_back(Native);

    amounts_out.push_back(31415);
    colors_out.push_back(Green);

    tie(inSk, mixRing, outSk, outPk) = generate_test_transaction_keys(
            amounts_in, colors_in,
            10, index,
            amounts_out, colors_out
    );

    key msg = skGen();  // random message

#warning "parameter 'amount_keys' should be shared secret? yes, but for testing irrelevant"

    auto time_before = std::chrono::high_resolution_clock::now();

    auto mcrctsig = genMCRct(
            msg, inSk , amounts_in,  colors_in, to_dest_keyV(outPk), amounts_out, colors_out, mixRing, to_dest_keyV(outSk),
            NULL, NULL, index, outSk, false, hw::get_device("default")
    );

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::genMCRct_scale " << inputs << " " << outputs << " " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    time_before = std::chrono::high_resolution_clock::now();
    bool result=verMCRct(mcrctsig, false);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "mcrct::verMCRct_scale " << inputs << " " << outputs << " " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    ASSERT_TRUE(result);
}

void test_rctsig(int inputs, int outputs){
    //Ring CT Stuff
    //ct range proofs

    ctkeyV inSk, outSk, outPk;
    ctkeyM mixRing;

    vector<xmr_amount> amounts_in;
    vector<xmr_amount> amounts_out;

    int native = 0;
    for(int i=0; i<inputs; i++){
        amounts_in.push_back(42);
        native += 42;
    }

    for(int i=0; i<outputs-2; i++){
        amounts_out.push_back(1);
        native -= 1;
    }
    amounts_out.push_back(native);

    unsigned int index=1;


    tie(inSk, mixRing, outSk, outPk) = generate_test_rct_transaction_keys(
            amounts_in,
            10, index,
            amounts_out
    );

    key msg = skGen();  // random message

    auto time_before = std::chrono::high_resolution_clock::now();

    rctSig s = genRct(msg, inSk, to_rct_dest_keyV(outPk), amounts_out, mixRing, to_rct_dest_keyV(outSk), NULL, NULL, index, outSk, false, hw::get_device("default"));

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::genRct_scale " << inputs << " " << outputs << " " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    time_before = std::chrono::high_resolution_clock::now();
    bool result=rct::verRct(s);
    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::verRct_scale " << inputs << " " << outputs << " " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl << std::flush;

    ASSERT_TRUE(result);

}

TEST(mcringct, MCRctSig_scale) {
    for(int i=2; i< 30; i++)
    {
        test_mcrctsig(i,3);
        test_mcrctsig(3,i);
        test_mcrctsig(i,i);
    }

}

TEST(mcringct, RctSig_scale) {
    for(int i=2; i< 30; i++)
    {
        test_rctsig(i,3);
        test_rctsig(3,i);
        test_rctsig(i,i);
    }

}

TEST(mcringct, time_proveRctMG) {
    ctkeyV inSk, outSk, outPk;
    ctkeyM mixRing;

    unsigned int index=1;
    vector<xmr_amount> amounts_in({1,2,7});
    vector<xmr_amount> amounts_out({6,3,1});

    tie(inSk, mixRing, outSk, outPk) = generate_test_rct_transaction_keys(
            amounts_in,
    10, index,
    amounts_out
    );

    key txnZeroFeeKey = scalarmultH(d2h(0));
    key msg = skGen();

    auto time_before = std::chrono::high_resolution_clock::now();

    mgSig sig = rct::proveRctMG(
            msg,
            mixRing, inSk, outSk, outPk,
            NULL, NULL, index, txnZeroFeeKey, hw::get_device("default")
    );

    auto time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::proveRctMG " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    time_before = std::chrono::high_resolution_clock::now();

    auto res = verRctMG(sig, mixRing, outPk, txnZeroFeeKey, msg);

    time_after = std::chrono::high_resolution_clock::now();
    std::cerr << "rct::verRctMG " << std::chrono::duration_cast<std::chrono::microseconds>(time_after-time_before).count() << " micros" << std::endl;

    ASSERT_TRUE(res);
}