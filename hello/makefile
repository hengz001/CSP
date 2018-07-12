
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
	$(OBJ)/aes.o 
	$(CC) -o $(BIN)/hello \
	$(OBJ)/secret.o \
	$(OBJ)/tools.o \
	$(OBJ)/des.o \
	$(OBJ)/aes.o \
	$(LFLAGS)
		
$(OBJ)/secret.o: $(SRC)/secret.c
			$(CC) $(CFLAGS) $(SRC)/secret.c -o $@
			
$(OBJ)/tools.o: $(SRC)/tools.c
			$(CC) $(CFLAGS) $(SRC)/tools.c -o $@
			
$(OBJ)/des.o: $(SRC)/des.c
			$(CC) $(CFLAGS) $(SRC)/des.c -o $@

$(OBJ)/aes.o: $(SRC)/aes.c
			$(CC) $(CFLAGS) $(SRC)/aes.c -o $@			
			
			