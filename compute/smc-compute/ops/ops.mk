#Add inputs and outputs to the build variables
CPP_SRCS += \
../smc-compute/ops/BitLTC.cpp \
../smc-compute/ops/LTZ.cpp \
../smc-compute/ops/Mod2.cpp \
../smc-compute/ops/Mod2M.cpp \
../smc-compute/ops/Mod2MS.cpp \
../smc-compute/ops/Mult.cpp \
../smc-compute/ops/Operation.cpp \
../smc-compute/ops/EQZ.cpp \
../smc-compute/ops/PrefixMultiplication.cpp \
../smc-compute/ops/SDiv.cpp \
../smc-compute/ops/Trunc.cpp \
../smc-compute/ops/BitOps.cpp \
../smc-compute/ops/DotProduct.cpp \
../smc-compute/ops/Pow2.cpp \
../smc-compute/ops/BitDec.cpp \
../smc-compute/ops/AddBitwise.cpp \
../smc_compute/ops/PreOpL.cpp \
../smc-compute/ops/B2U.cpp \
../smc-compute/ops/PreOr.cpp \
../smc-compute/ops/TruncS.cpp \
../smc-compute/ops/Inv.cpp \
../smc-compute/ops/TruncPr.cpp \
../smc-compute/ops/PrivIndex.cpp \
../smc-compute/ops/Random.cpp \
../smc-compute/ops/PrviPtr.cpp \
../smc-compute/ops/AppRcr.cpp \
../smc-compute/ops/IntAppRcr.cpp \
../smc-compute/ops/Norm.cpp \
../smc-compute/ops/Open.cpp \
../smc-compute/ops/BitAdd.cpp \
../smc-compute/ops/BitLT.cpp \
../smc-compute/ops/BitEq.cpp\
../smc-compute/ops/BitMul.cpp\
../smc-compute/ops/BitSum.cpp

OBJS += \
./smc-compute/ops/BitLTC.o \
./smc-compute/ops/LTZ.o \
./smc-compute/ops/Mod2.o \
./smc-compute/ops/Mod2M.o \
./smc-compute/ops/Mod2MS.o \
./smc-compute/ops/Mult.o \
./smc-compute/ops/Operation.o \
./smc-compute/ops/EQZ.o \
./smc-compute/ops/PrefixMultiplication.o \
./smc-compute/ops/SDiv.o \
./smc-compute/ops/Trunc.o \
./smc-compute/ops/BitOps.o \
./smc-compute/ops/DotProduct.o \
./smc-compute/ops/Pow2.o \
./smc-compute/ops/BitDec.o \
./smc-compute/ops/AddBitwise.o \
./smc-compute/ops/PreOpL.o \
./smc-compute/ops/B2U.o \
./smc-compute/ops/PreOr.o \
./smc-compute/ops/TruncS.o \
./smc-compute/ops/Inv.o \
./smc-compute/ops/TruncPr.o \
./smc-compute/ops/PrivIndex.o \
./smc-compute/ops/Random.o \
./smc-compute/ops/IntDiv.o \
./smc-compute/ops/PrivPtr.o \
./smc-compute/ops/AppRcr.o \
./smc-compute/ops/IntAppRcr.o \
./smc-compute/ops/Norm.o \
./smc-compute/ops/Open.o \
./smc-compute/ops/BitAdd.o \
./smc-compute/ops/BitLT.o \
./smc-compute/ops/BitEq.o\
./smc-compute/ops/BitMul.o\
./smc-compute/ops/BitSum.o

CPP_DEPS += \
./smc-compute/ops/BitLTC.d \
./smc-compute/ops/LTZ.d \
./smc-compute/ops/Mod2.d \
./smc-compute/ops/Mod2M.d \
./smc-compute/ops/Mod2MS.d \
./smc-compute/ops/Mult.d \
./smc-compute/ops/Operation.d \
./smc-compute/ops/EQZ.d \
./smc-compute/ops/PrefixMultiplication.d \
./smc-compute/ops/SDiv.d \
./smc-compute/ops/Trunc.d \
./smc-compute/ops/BitOps.d \
./smc-compute/ops/DotProduct.d \
./smc-compute/ops/Pow2.d \
./smc-compute/ops/BitDec.d \
./smc-compute/ops/AddBitwise.d \
./smc-compute/ops/PreOpL.d \
./smc-compute/ops/B2U.d \
./smc-compute/ops/PreOr.d \
./smc-compute/ops/TruncS.d \
./smc-compute/ops/Inv.d \
./smc-compute/ops/TruncPr.d \
./smc-compute/ops/PrivIndex.d \
./smc-compute/ops/Random.d \
./smc-compute/ops/IntDiv.d \
./smc-compute/ops/PrivPtr.d \
./smc-compute/ops/AppRcr.d \
./smc-compute/ops/IntAppRcr.d \
./smc-compute/ops/Norm.d  \
./smc-compute/ops/Open.d \
./smc-compute/ops/BitAdd.d  \
./smc-compute/ops/BitLT.d  \
./smc-compute/ops/BitEq.d\
./smc-compute/ops/BitMul.d\
./smc-compute/ops/BitSum.d

#Rules for building source in ops
smc-copmpute/ops%.o: ../smc-compute/ops/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished Building $<'
	@Echo ' '


