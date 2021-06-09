#!/bin/bash

rm -rf extracted
mkdir -p extracted

ECIES_MEASUREMENTS=(
  # Info
  EciesInfoGet

  # Enc
  EciesEncEnd

  # Dec
  EciesDecEnd

  # Refresh/DKG
  EciesBroadcastSharingEnd
  EciesAssembleShareEnd
  EciesGenProofEnd
  EciesInterpolatePublicEnd
  EciesRefreshTotalEnd)

for (( i=0; i<${#ECIES_MEASUREMENTS[@]}; i++ ));
do
  ARR=$(cat log.txt | grep "PerfMeas:${ECIES_MEASUREMENTS[$i]}" | grep -Eo '[0-9]+$')
  echo $ARR | sed 's/ /,/g' > "extracted/${ECIES_MEASUREMENTS[$i]}.csv"
done