
BIN = $(PWD)/bin
INC = $(PWD)/inc
LIB = $(PWD)/lib
OBJ = $(PWD)/obj
SRC = $(PWD)/src

CC = gcc -g
CFLAGS = -c -I $(INC) -Wall -Wstrict-prototypes -O3
LFLAGS = -L$(LIB) -lcrypto

all: zh 

strip:
	strip $(BIN)/*

clean:
	rm -rf $(OBJ)/*.o
	rm -rf $(LIB)/*.a
	rm -rf $(BIN)/*
	
zh: $(OBJ)/secret.o \
	$(OBJ)/tools.o \
	$(OBJ)/des.o \
	$(OBJ)/aes.o \
	$(OBJ)/rsa.o \
	$(OBJ)/md5.o \
	$(OBJ)/sm2.o \
	$(OBJ)/sm3.o \
	$(OBJ)/sm4.o \
	$(OBJ)/sm9.o \
	$(OBJ)/random.o
	$(CC) -o $(BIN)/hello \
	$(OBJ)/secret.o \
	$(OBJ)/tools.o \
	$(OBJ)/des.o \
	$(OBJ)/aes.o \
	$(OBJ)/rsa.o \
	$(OBJ)/md5.o \
	$(OBJ)/sm2.o \
	$(OBJ)/sm3.o \
	$(OBJ)/sm4.o \
	$(OBJ)/sm9.o \
	$(OBJ)/random.o \
	$(LFLAGS)
		
$(OBJ)/secret.o: $(SRC)/secret.c
			$(CC) $(CFLAGS) $(SRC)/secret.c -o $@
			
$(OBJ)/tools.o: $(SRC)/tools.c
			$(CC) $(CFLAGS) $(SRC)/tools.c -o $@
			
$(OBJ)/des.o: $(SRC)/des.c
			$(CC) $(CFLAGS) $(SRC)/des.c -o $@

$(OBJ)/aes.o: $(SRC)/aes.c
			$(CC) $(CFLAGS) $(SRC)/aes.c -o $@
			
$(OBJ)/rsa.o: $(SRC)/rsa.c
			$(CC) $(CFLAGS) $(SRC)/rsa.c -o $@			
			
$(OBJ)/md5.o: $(SRC)/md5.c
			$(CC) $(CFLAGS) $(SRC)/md5.c -o $@
			
$(OBJ)/sm2.o: $(SRC)/sm2.c
			$(CC) $(CFLAGS) $(SRC)/sm2.c -o $@
			
$(OBJ)/sm3.o: $(SRC)/sm3.c
			$(CC) $(CFLAGS) $(SRC)/sm3.c -o $@
			
$(OBJ)/sm4.o: $(SRC)/sm4.c
			$(CC) $(CFLAGS) $(SRC)/sm4.c -o $@			
			
$(OBJ)/sm9.o: $(SRC)/sm9.c
			$(CC) $(CFLAGS) $(SRC)/sm9.c -o $@			
			
$(OBJ)/random.o: $(SRC)/random.c
			$(CC) $(CFLAGS) $(SRC)/random.c -o $@			
			