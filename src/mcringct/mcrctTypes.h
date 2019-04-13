#ifndef MONERO_MCRCTTYPES_H
#define MONERO_MCRCTTYPES_H

#include <vector>
#include <utility>

#include "ringct/rctTypes.h"

using namespace rct;

namespace mcrct {

    struct mcctkey : ctkey {
        key color; // blinding factor of Color Comitment or Color commitment
        //explicit operator ctkey() const {ctkey tmp{}; tmp.dest=dest; tmp.mask=mask; return tmp;}
    };
    typedef std::vector<mcctkey> mcctkeyV;
    typedef std::vector<mcctkeyV> mcctkeyM;

    // conversion
    inline ctkey mcct2ct(mcctkey mcctk) {return static_cast<ctkey>(mcctk);}
    inline ctkeyV mcctV2ctV(mcctkeyV mcctkV) {return ctkeyV(mcctkV.begin(), mcctkV.end());}
    inline ctkeyM mcctM2ctM(mcctkeyM mcctkM) {
        ctkeyV tmp(mcctkM[0].size());
        ctkeyM ctkM(mcctkM.size(), tmp);
        for (size_t i=0; i<mcctkM.size(); i++) {
            for (size_t j = 0; j<mcctkM[0].size(); j++) {
                ctkM[i][j] = static_cast<ctkey>(mcctkM[i][j]);
            }
        }
        return ctkM;
    }

    struct colorSig {
        keyM r;
        key c1;
    };

    struct mcrctSigPrunable : rctSigPrunable {
        //std::vector<std::pair<key, key>> colorsOutEqual;
        struct colorSig colorSig;
        //TODO: borromean output color range
    };

    struct mcrctSig {
        uint8_t type;
        key message;
        mcctkeyM mixRing; //the set of all pubkeys / copy
        //pairs that you mix with
        keyV pseudoOuts; //C - for simple rct
        std::vector<ecdhTuple> ecdhInfo;
        mcctkeyV outPk;
        mcctkeyV tmpPk;
        xmr_amount txnFee; // contains b
        mcrctSigPrunable p;

        template<bool W, template <bool> class Archive>
        bool serialize_mcrctsig_base(Archive<W> &ar, size_t inputs, size_t outputs)
        {
            FIELD(type)
            if (type == RCTTypeNull)
                return true;
            if (type != RCTTypeFull && type != RCTTypeFullBulletproof && type != RCTTypeSimple && type != RCTTypeSimpleBulletproof)
                return false;
            VARINT_FIELD(txnFee)
            // inputs/outputs not saved, only here for serialization help
            // FIELD(message) - not serialized, it can be reconstructed
            // FIELD(mixRing) - not serialized, it can be reconstructed
            if (type == RCTTypeSimple) // moved to prunable with bulletproofs
            {
                ar.tag("pseudoOuts");
                ar.begin_array();
                PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, pseudoOuts);
                if (pseudoOuts.size() != inputs)
                    return false;
                for (size_t i = 0; i < inputs; ++i)
                {
                    FIELDS(pseudoOuts[i])
                    if (inputs - i > 1)
                        ar.delimit_array();
                }
                ar.end_array();
            }

            ar.tag("ecdhInfo");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, ecdhInfo);
            if (ecdhInfo.size() != outputs){
                return false;
            }
            for (size_t i = 0; i < outputs; ++i)
            {
                FIELDS(ecdhInfo[i])
                if (outputs - i > 1)
                    ar.delimit_array();
            }
            ar.end_array();

            ar.tag("outPk");
            ar.begin_array();
            PREPARE_CUSTOM_VECTOR_SERIALIZATION(outputs, outPk);
            if (outPk.size()*2 != outputs) {
                return false;
            }
            for (size_t i = 0; i < outPk.size(); ++i)
            {
                FIELDS(outPk[i].mask)
                FIELDS(outPk[i].color)
                if (outputs - i > 1)
                    ar.delimit_array();
            }
            ar.end_array();
            return true;
        }
    };


    // RANGEPROOFS sind nur für \in [0, 2^64]
    // proveRctMG sollte als erstes auf colrct umgeschrieben werden denke ich :)

}

#endif //MONERO_MCRCTTYPES_H
