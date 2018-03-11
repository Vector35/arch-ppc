/* these are the flags in cr0
	(the default condition field in condition register CR)

PPC docs conceptualize this in a reverse bit order of sorts:

     CR0         CR1
 ----------- ----------- 
 b0 b1 b2 b3 b4 b5 b6 b7 
+--+--+--+--+--+--+--+--+ ...
|LT|GT|EQ|SO|LT|GT|EQ|SO|
+--+--+--+--+--+--+--+--+  

or is it: |SO|LT|GT|EQ
eg: cmp a, b
if a<b  then c=0b100 (not setting SO, setting LT)
if a>b  then c=0b010 (not setting SO, setting GT)
if a==b then c=0b001 (not setting SO, setting EQ)
 */

#define IL_FLAG_LT 0
#define IL_FLAG_GT 1
#define IL_FLAG_EQ 2
#define IL_FLAG_SO 3
#define IL_FLAG_LT_1 4
#define IL_FLAG_GT_1 5
#define IL_FLAG_EQ_1 6
#define IL_FLAG_SO_1 7
#define IL_FLAG_LT_2 8
#define IL_FLAG_GT_2 9
#define IL_FLAG_EQ_2 10
#define IL_FLAG_SO_2 11
#define IL_FLAG_LT_3 12
#define IL_FLAG_GT_3 13
#define IL_FLAG_EQ_3 14
#define IL_FLAG_SO_3 15
#define IL_FLAG_LT_4 16
#define IL_FLAG_GT_4 17
#define IL_FLAG_EQ_4 18
#define IL_FLAG_SO_4 19
#define IL_FLAG_LT_5 20
#define IL_FLAG_GT_5 21
#define IL_FLAG_EQ_5 22
#define IL_FLAG_SO_5 23
#define IL_FLAG_LT_6 24
#define IL_FLAG_GT_6 25
#define IL_FLAG_EQ_6 26
#define IL_FLAG_SO_6 27
#define IL_FLAG_LT_7 28
#define IL_FLAG_GT_7 29
#define IL_FLAG_EQ_7 30
#define IL_FLAG_SO_7 31

/* and now the fixed-point exception register XER */
#define IL_FLAG_XER_SO 32 /* [s]ummary [o]verflow */
#define IL_FLAG_XER_OV 33 /* [ov]erflow */
#define IL_FLAG_XER_CA 34 /* [ca]rry */

/* the different types of influence an instruction can have over flags */
#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_CR0_S 1
#define IL_FLAGWRITE_CR0_U 2
#define IL_FLAGWRITE_CR1_S 3
#define IL_FLAGWRITE_CR1_U 4
#define IL_FLAGWRITE_CR2_S 5
#define IL_FLAGWRITE_CR2_U 6
#define IL_FLAGWRITE_CR3_S 7
#define IL_FLAGWRITE_CR3_U 8
#define IL_FLAGWRITE_CR4_S 9
#define IL_FLAGWRITE_CR4_U 10
#define IL_FLAGWRITE_CR5_S 11
#define IL_FLAGWRITE_CR5_U 12
#define IL_FLAGWRITE_CR6_S 13
#define IL_FLAGWRITE_CR6_U 14
#define IL_FLAGWRITE_CR7_S 15
#define IL_FLAGWRITE_CR7_U 16
#define IL_FLAGWRITE_XER 17
#define IL_FLAGWRITE_XER_CA 18
#define IL_FLAGWRITE_XER_OV_SO 19

/* the different classes of writes to each cr */
#define IL_FLAGCLASS_NONE 0
#define IL_FLAGCLASS_CR0_S 1
#define IL_FLAGCLASS_CR0_U 2
#define IL_FLAGCLASS_CR1_S 3
#define IL_FLAGCLASS_CR1_U 4
#define IL_FLAGCLASS_CR2_S 5
#define IL_FLAGCLASS_CR2_U 6
#define IL_FLAGCLASS_CR3_S 7
#define IL_FLAGCLASS_CR3_U 8
#define IL_FLAGCLASS_CR4_S 9
#define IL_FLAGCLASS_CR4_U 10
#define IL_FLAGCLASS_CR5_S 11
#define IL_FLAGCLASS_CR5_U 12
#define IL_FLAGCLASS_CR6_S 13
#define IL_FLAGCLASS_CR6_U 14
#define IL_FLAGCLASS_CR7_S 15
#define IL_FLAGCLASS_CR7_U 16

bool GetLowLevelILForPPCInstruction(Architecture *arch, LowLevelILFunction& il, const uint8_t *data, uint64_t addr, decomp_result *res);
