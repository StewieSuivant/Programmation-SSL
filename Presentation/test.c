len = 0;
while(len < sizeCookie){
  C = AliceEncrypt(M);
  send(Alice, Oscar, C);
  C = OscarModifyLastBlock(C);
  send(Oscar, Bob, C);
  D = BobDecrypt(C);
    if(BobVerifyPadding(D) == True){
      send(Bob,[Oscar,Alice], "VALIDE");
      OscarFindByte(C);
      AliceRealign(M);
      len++;
    }
    else{
      send(Bob,[Oscar,Alice], "INVALIDE");      
      renegociateKey(Alice, Bob);
    }
 }
