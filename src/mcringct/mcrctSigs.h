#ifndef MONERO_MCRCTSIGS_H
#define MONERO_MCRCTSIGS_H

#include "mcrctTypes.h"
#include "device/device.hpp"


namespace mcrct {

    std::tuple<mcctkey, mcctkey> mcctskpkGen(xmr_amount amount, key amount_color);

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
    );

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveColoredRange(key & C, key & mask, const xmr_amount & amount, const key & Fct);
    bool verColoredRange(const key & C, const rangeSig & as, const key & Fct);

    colorSig genColBorromean(const keyV & x, const keyM & P, const std::vector<size_t> & indices);
    bool verifyColBorromean(colorSig bb, const keyM & P);

    mcrctSig genMCRct(const key &message, const mcctkeyV & inSk, const std::vector<xmr_amount> & amounts_in, const std::vector<key> & Colors_in,  const keyV & destinations,
                    const std::vector<xmr_amount> & amounts, const std::vector<key> & Colors,
                    const mcctkeyM &mixRing, const keyV &amount_keys, const multisig_kLRki *kLRki, multisig_out *msout,
                    unsigned int index, mcctkeyV &outSk, bool bulletproof, hw::device &hwdev);

    bool verMCRct(const mcrctSig & rv, bool semantics);

    bool verMCRctMG(const mgSig &mg, const mcctkeyM & pubs, const mcctkeyV & tmpPk, const mcctkeyV & outPk, key txnFeeKey, const key &message);

}

#endif //MONERO_MCRCTSIGS_H
