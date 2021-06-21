#!/bin/bash

LABEL=$1

LOGFILE=log.txt

rm -rf extracted
mkdir -p extracted

ECIES_MEASUREMENTS=(
  # Info
  EciesInfoGet

  # Enc
  EciesEncEnd

  EciesEncGenRand
  EciesEncPubCompute
  EciesEncSharedSecretCompute
  EciesEncKdf
  EciesEncSymmCompute
  EciesEncMacCompute

  EciesEncCiphertextBytes
  EciesEncPkBits

  # Dec
  EciesDecEnd

  EciesDecShareDec
  EciesDecShareProof
  EciesDecShareTotal

  EciesDecCombineKdf
  EciesDecCombineMac
  EciesDecCombineDecrypt
  EciesDecCombineVerify
  EciesDecCombineInterpolate
  EciesDecCombineTotal

  # Refresh/DKG
  EciesBroadcastSharingEnd
  EciesAssembleShareEnd
  EciesGenProofEnd
  EciesInterpolatePublicEnd
  EciesRefreshTotalEnd)

RSA_MEASUREMENTS=(
  # Info
  RsaInfoGet

  # Gen
  RsaStoreEnd
  RsaGenEnd
  RsaGenTotal

  # Enc
  RsaEncEnd

  RsaEncGenSym
  RsaEncSymEnc
  RsaEncHash
  RsaEncPad
  RsaEncExp

  RsaEncCiphertextBytes
  RsaEncPkBits

  # Dec
  RsaDecEnd

  RsaDecShareDec
  RsaDecShareProof
  RsaDecShareTotal

  # RsaDecCombineRequest
  RsaDecCombineVerify
  RsaDecCombineInterpolate
  RsaDecCombineUnpad
  RsaDecCombineDecrypt
  RsaDecCombineHash
  RsaDecCombineTotal

  # Refresh
  RsaRefreshAdditiveEnd
  RsaRefreshAssembleAdditiveEnd
  RsaRefreshGeneratePolynomialEnd
  RsaRefreshAssemblePolynomialEnd
  RsaRefreshTotalEnd)

KYBER_MEASUREMENTS=(
  # Info
  KyberInfoGet

  # Gen
  KyberStoreEnd
  KyberGenEnd
  KyberGenTotal

  # Enc
  KyberEncEnd

  KyberEncRand
  KyberEncGHash
  KyberEncCpa
  KyberEncKdf
  KyberEncSym

  KyberEncCiphertextBytes
  KyberEncPkBits

  # Dec
  KyberDecEnd

  KyberDecShareTotal

  KyberDecCombineAdd
  KyberDecCombineHashG
  KyberDecCombineEnc
  KyberDecCombineKdf
  KyberDecCombineSym)

for (( i=0; i<${#ECIES_MEASUREMENTS[@]}; i++ ));
do
  ARR=$(cat $LOGFILE | grep "PerfMeas:${ECIES_MEASUREMENTS[$i]}" | grep -Eo '[0-9]+$')
  [[ ! -z $ARR ]] && echo $ARR | sed 's/ /,/g' > "extracted/${ECIES_MEASUREMENTS[$i]}${LABEL}.csv"
done

for (( i=0; i<${#RSA_MEASUREMENTS[@]}; i++ ));
do
  ARR=$(cat $LOGFILE | grep "PerfMeas:${RSA_MEASUREMENTS[$i]}" | grep -Eo '[0-9]+$')
  [[ ! -z $ARR ]] && echo $ARR | sed 's/ /,/g' > "extracted/${RSA_MEASUREMENTS[$i]}${LABEL}.csv"
done

for (( i=0; i<${#KYBER_MEASUREMENTS[@]}; i++ ));
do
  ARR=$(cat $LOGFILE | grep "PerfMeas:${KYBER_MEASUREMENTS[$i]}" | grep -Eo '[0-9]+$')
  [[ ! -z $ARR ]] && echo $ARR | sed 's/ /,/g' > "extracted/${KYBER_MEASUREMENTS[$i]}${LABEL}.csv"
done