import {
    ByteString,
    SmartContract,
    prop,
    method,
    assert,
    PubKey,
    Sig,
    hash160,
    FixedArray,
} from 'scrypt-ts'
import {
    PrevoutsCtx,
    SHPreimage,
    SigHashUtils,
    SpentScriptsCtx,
} from '../utils/sigHashUtils'
import { MAX_INPUT, STATE_OUTPUT_INDEX, int32 } from '../utils/txUtil'
import { TxProof, XrayedTxIdPreimg3 } from '../utils/txProof'
import { PreTxStatesInfo, StateUtils } from '../utils/stateUtils'
import { CAT20State, CAT20Proto } from './cat20Proto'
import { GuardConstState, GuardProto } from './guardProto'
import { Backtrace, BacktraceInfo } from '../utils/backtrace'

export type GuardInfo = {
    tx: XrayedTxIdPreimg3
    inputIndexVal: int32
    outputIndex: ByteString
    guardState: GuardConstState
}

export type TokenUnlockArgs = {
    // `true`: spend by user, `false`: spend by contract
    isUserSpend: boolean

    // user spend args
    userPubKeyPrefix: ByteString
    userPubKey: PubKey
    userSig: Sig

    // contract spend arg
    contractInputIndex: int32
}


export class CAT20 extends SmartContract { // SC term not good for Bitcoin-based system!
    @prop()
    minterScript: ByteString

    @prop()
    guardScript: ByteString

    constructor(minterScript: ByteString, guardScript: ByteString) {
        super(...arguments)
        this.minterScript = minterScript
        this.guardScript = guardScript
    }

    @method()
    public unlock(
        tokenUnlockArgs: TokenUnlockArgs,

        // verify preTx data part
        /*    Pay attention 
        *    to verification part.
        *            
        *     Mainly achieved with
        * `SigHashUtils` &  `StateUtils` lib
        *
        * this LIBs Usage 
        *  `SigHashUtils`:
        *    - checkSHPreimage()
        *    - Gx
        *    - checkPrevoutsCtx()
        *    - checkSpentScriptsCtx()
        *  `StateUtils`:
        *    - verifyPreStateHash()
        *
        */
        
        preState: CAT20State,
        preTxStatesInfo: PreTxStatesInfo,

        // amount check guard
        guardInfo: GuardInfo,
        
        // backtrace
        backtraceInfo: BacktraceInfo,
        // common args
        // current tx info
        shPreimage: SHPreimage, // How is it provided in tx?
        prevoutsCtx: PrevoutsCtx, // Ctx: Contextual information about previous outputs. `ContextTX?`
        spentScripts: SpentScriptsCtx
    ) {
        // Check sighash preimage.
        assert(
            this.checkSig(
                SigHashUtils.checkSHPreimage(shPreimage),
                SigHashUtils.Gx 
            )
            /*
            * Uses SigHashUtils to validate the preimage and checks 
            * the signature against a predefined value (Gx).
            */
            ,
            'preimage check error'
        )
        // check ctx
        SigHashUtils.checkPrevoutsCtx(
            prevoutsCtx,
            shPreimage.hashPrevouts,
            shPreimage.inputIndex
        )
        SigHashUtils.checkSpentScriptsCtx(
            spentScripts,
            shPreimage.hashSpentScripts
        )
        // verify state
        StateUtils.verifyPreStateHash(
            preTxStatesInfo,
            CAT20Proto.stateHash(preState),
            backtraceInfo.preTx.outputScriptList[STATE_OUTPUT_INDEX],
            prevoutsCtx.outputIndexVal
        )
        /*
        *  Computes the state hash using CAT20Proto and verifies 
        *  it against the stored state information.
        *
        */
        
        const preScript = spentScripts[Number(prevoutsCtx.inputIndexVal)]
        Backtrace.verifyToken(
            prevoutsCtx.spentTxhash,
            backtraceInfo,
            this.minterScript,
            preScript
        )
        /*
        *  Uses the Backtrace utility to verify the token's 
        *  lineage against the minterScript and the previous script.
        */
        
        // make sure the token is spent with a valid guard
        this.valitateGuard(
            guardInfo,
            preScript,
            preState,
            prevoutsCtx.inputIndexVal,
            prevoutsCtx.prevouts,
            spentScripts
        )
        
        if (tokenUnlockArgs.isUserSpend) {
            // unlock token owned by user key
            assert(
                hash160(
                    tokenUnlockArgs.userPubKeyPrefix +
                        tokenUnlockArgs.userPubKey
                ) == preState.ownerAddr
            )
            assert(
                this.checkSig(
                    tokenUnlockArgs.userSig,
                    tokenUnlockArgs.userPubKey
                )
            )
        /*
        *  - Hashes the user's public key prefix and public key 
        *   to ensure it matches the stored owner's address.
        *  - Verifies the user's signature to authenticate the spend request.
        *
        */
        } else {
            // unlock token owned by contract script
            assert(
                preState.ownerAddr ==
                    hash160(
                        spentScripts[Number(tokenUnlockArgs.contractInputIndex)]
                    )
            )
            /*
            * Ensures that the owner's address matches 
            * the hash of the script at the specified 
            * contract input index.
            * [Clarify InputIndex for contract]
            */
            
        }
    }
    // According to GPT: Ensures that the token spend operation adheres to the guard conditions, 
    // maintaining the integrity and security of the token ecosystem.
    /*
    * The question of integrity and security should be 
    * deeply considered as we rely on Bitcoin we should be
    * able to inherit of it. 
    * If the transaction is accepted by node can we 
    * assume something about security consideration? 
    *
    */
    @method()
    valitateGuard(
        guardInfo: GuardInfo,
        preScript: ByteString,
        preState: CAT20State,
        inputIndexVal: int32,
        prevouts: FixedArray<ByteString, typeof MAX_INPUT>,
        spentScripts: SpentScriptsCtx
    ): boolean {
        // check amount script
        const guardHashRoot = GuardProto.stateHash(guardInfo.guardState)
        assert(guardInfo.guardState.tokenScript == preScript)
        assert(
            StateUtils.getStateScript(guardHashRoot, 1n) ==
                guardInfo.tx.outputScriptList[STATE_OUTPUT_INDEX]
        )
        assert(preState.amount > 0n)
        assert(
            guardInfo.guardState.inputTokenAmountArray[Number(inputIndexVal)] ==
                preState.amount
        )
        const guardTxid = TxProof.getTxIdFromPreimg3(guardInfo.tx)
        assert(
            prevouts[Number(guardInfo.inputIndexVal)] ==
                guardTxid + guardInfo.outputIndex
        )
        assert(
            spentScripts[Number(guardInfo.inputIndexVal)] == this.guardScript
        )
        return true
    }
}
