/**
 * Authors: Ulm University, Institute for Distributed Systems
 * Lukas Müller, Michael Steck, Felix Engelmann
 */
#ifndef MONERO_MCRCTSIGS_H
#define MONERO_MCRCTSIGS_H

#include "mcrctTypes.h"
#include "device/device.hpp"


namespace mcrct {

    std::tuple<mcctkey, mcctkey> mcctskpkGen(xmr_amount amount, key amount_color);

    mgSig proveMCRctMGSimple(
            const key &message, const mcctkeyV &pubs,
            const mcctkey &inSk,
            const xmr_amount &amount_in,
            const mcctkey &tmpSk,
            const mcctkey &tmpPk,
            const multisig_kLRki *kLRki, key *mscout, unsigned int index,
            hw::device &hwdev
    );

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveColoredRange(key &C, key &mask, const xmr_amount &amount, const key &Fct);

    bool verColoredRange(const key &C, const rangeSig &as, const key &Fct);

    //colorSig genColBorromean(const keyV &x, const keyM &P, const std::vector<size_t> &indices); old stuff
    //bool verifyColBorromean(colorSig bb, const keyM &P);

    std::tuple<key, key> proveConservation(
            const mcctkeyV &outPk,
            const mcctkeyV &outSk,
            const std::vector<xmr_amount> &amounts_in,
            const std::vector<xmr_amount> &amounts_out,
            const mcctkeyV &tmpPk,
            const mcctkeyV &tmpSk,
            key txnFeeKey
    );

    bool verifyConservation(
            const mcctkeyV &outPk,
            const mcctkeyV &tmpPk,
            const key &v_pk,
            const key &r,
            key txnFeeKey
            );

    equalSig proveEqual(mcctkey fromPk, ctkey toPk, xmr_amount amount, ctkey fromSk, ctkey toSk);
    bool verifyEqual(equalSig s, mcctkey fromPk, ctkey toPk);

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
                            hw::device &hwdev);

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
                            hw::device &hwdev);

    xmr_amount populateFromBlockchainSimple(mcctkeyV &mixRing, const mcctkey &inPk, unsigned int mixin);

    void getKeyFromBlockchain(mcctkey &a, size_t reference_index);

    bool verMCRctSimple(const mcrctSig &rv, bool semantics);

    bool verMCRctMGSimple(const mgSig &mg, const mcctkeyV &pubs, const mcctkey &tmpPk, const key &message);
}

#endif //MONERO_MCRCTSIGS_H
