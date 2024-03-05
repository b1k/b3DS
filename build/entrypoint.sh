#!/bin/bash

###########################################
### commands
###########################################
ECHO="echo -e"

###########################################
### environments
###########################################
TO_DECRP_FOLDER=/to_decrypt
TO_ENCRP_FOLDER=/to_encrpt
OUTPUT_FOLDER=/output

DECRP=/b3DS/b3DSDecrypt.py
ENCRP=/b3DS/b3DSEncrypt.py

###########################################
### start prozess
###########################################
$ECHO "

Start Converting
Start Date: $(date)

"
mkdir -p $TO_DECRP_FOLDER $TO_ENCRP_FOLDER $OUTPUT_FOLDER
chmod 777 -R $TO_DECRP_FOLDER $TO_ENCRP_FOLDER $OUTPUT_FOLDER

###########################################
### decryption prozess
###########################################
TO_DECRP_FILES_NUMBER=$(ls $TO_DECRP_FOLDER/* 2>/dev/null | wc -l)
$ECHO "
Found $TO_DECRP_FILES_NUMBER files for decryption
"

if [ $TO_DECRP_FILES_NUMBER -gt 0 ]; then
  cd $TO_DECRP_FOLDER
  for i in $(ls .) ; do
    $ECHO "Decryption $i"
    python $DECRP $i
    mv $i $OUTPUT_FOLDER/decr_$i
  done
fi

###########################################
### encryption prozess
###########################################
TO_ENCRP_FILES_NUMBER=$(ls $TO_ENCRP_FOLDER/* 2>/dev/null | wc -l)
$ECHO "
Found $TO_ENCRP_FILES_NUMBER files for encryption
"

if [ $TO_ENCRP_FILES_NUMBER -gt 0 ]; then
  cd $TO_ENCRP_FOLDER
  for i in $(ls .) ; do
    $ECHO "Encryption $i"
    python $ENCRP $i
    mv $i $OUTPUT_FOLDER/encr_$i
  done
fi

$ECHO "
Finish Converting
End Date: $(date)
"