/**
 * Authors: Ulm University, Institute for Distributed Systems
 * Lukas Müller, Michael Steck, Felix Engelmann
 */
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
        std::vector<std::pair<key, key>> colorsOutEqual;
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
                return ar.stream().good();
            if (type != RCTTypeFull && type != RCTTypeSimple && type != RCTTypeBulletproof && type != RCTTypeBulletproof2)
                return false;
            VARINT_FIELD(txnFee)
            // inputs/outputs not saved, only here for serialization help
            // FIELD(message) - not serialized, it can be reconstructed
            // FIELD(mixRing) - not serialized, it can be reconstructed
            if (type == RCTTypeSimple) // moved to prunable with bulletproofs
            {
                //TODO: changes done here are _hic sunt dracones_
                ar.tag("tmpPk");
                ar.begin_array();
                PREPARE_CUSTOM_VECTOR_SERIALIZATION(inputs, tmpPk);
                if (tmpPk.size() != inputs)
                    return false;
                for (size_t i = 0; i < inputs; ++i)
                {
                    FIELDS(tmpPk[i].mask)
                    FIELDS(tmpPk[i].color)
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
}

#endif //MONERO_MCRCTTYPES_H
