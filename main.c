/*
 * 2022 Ivan Babintsev (C)
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>


/* Allowed programs HASH database */
const char *ALLOWED_PROG_HASHS[] = { 
    "c72960978b5e4288e6ba3b34ee9b47627115ca414e356c45e68b671ce4fdaaa7",    // allow certmgr run
};

const size_t HAHS_LENGTH = sizeof(ALLOWED_PROG_HASHS)/sizeof(ALLOWED_PROG_HASHS[0]);


/* 
 * Decrypt 1 byte with salt 0xFF 
 */
int 
ByteDecryptor(encryptedByte)
    int encryptedByte;
{    
    int src = encryptedByte;
    int decryptedByte;   

    asm ("mov %1, %0\n\t"
        "xor $0xFF, %0"
        : "=r" (decryptedByte) 
        : "r" (src));

    return decryptedByte;

}


/* 
 * Generate private string in secrity mode  
 */
void 
GetSecuredString(inputBuffer, securedBuffer, inputLength)
    int *inputBuffer;
    char *securedBuffer;
    int inputLength;
{
    
    for ( int i = 0; i < inputLength; i++ ) {
        int decodedByte = ByteDecryptor(inputBuffer[i]);
        char ch = (char) decodedByte;
        securedBuffer[i] = ch;
    }

}



/*
 * Check SHA256 hash in allowed program list
 */

bool CheckHash(hash)
    char *hash;
    {
        bool flag = false;
        for (int i = 0; i < HAHS_LENGTH; i++) {
            if (!strcmp(ALLOWED_PROG_HASHS[i], hash)) {
                flag = true;
                break;
            }
        }

        return flag;

    }


/*
 * Program entry point
 */
int main(int argc, char* argv[]) {
    char cwd[255];
    char subprog[255];
    char command[255];
    

    /* Encrypted user name in bytecodes */
    int usernameInputBuffer [] = { 0x8a, 0x96, 0x8b, 0x8c, 0x9e, 0x9b, 0x92, 0x96, 0x91 };
    
    /* Prepare buffer for username */
    int length_uname = (int)(sizeof(usernameInputBuffer) / sizeof(usernameInputBuffer[0]));
    char *usernameBuffer = malloc(sizeof(char) * length_uname);

    /* Encrypted user password in bytecodes */
    int passwordInputBuffer [] = { 0xaf, 0xbb, 0xab, 0xa3, 0xde, 0xc8, 0xca, 0xc8, 0x8f, 0x93, 0x99, 0xa3, 0xde };
    
    /* Prepare output buffer for password */
    int length_password = (int)(sizeof(passwordInputBuffer) / sizeof(passwordInputBuffer[0]));
    char *passwordBuffer = malloc(sizeof(char) * length_password);

    /* Generate username in secure mode */
    GetSecuredString(usernameInputBuffer, usernameBuffer, length_uname);

    /* Generate password in secure mode */
    GetSecuredString(passwordInputBuffer, passwordBuffer, length_password);   
    
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
    } 
    else {
       perror("getcwd() error");
    }

    strcpy(subprog, "\"");
    strcat(subprog, cwd);
    strcat(subprog, "/egg");
    strcat(subprog, "\"");

    char checksum[255];
    char fileMetka[255];

    strcpy(fileMetka, cwd);
    strcat(fileMetka, "/");
    strcat(fileMetka, "metka");

    strcpy(checksum, "shasum -a256 ");
    strcat(checksum, subprog);
    strcat(checksum, " | awk '{print $1}' >");
    strcat(checksum, "\"");
    strcat(checksum, fileMetka);
    strcat(checksum, "\"");    
    system(checksum);

    
    //-------Read SHA256 hash from metka file-------
    char strHASH[255];
    FILE *fptr;

    if ((fptr = fopen(fileMetka, "r")) == NULL) {
        printf("Error opening file!");
        exit(1);
    }

    fscanf(fptr,"%s", strHASH);
    fclose(fptr); 

    
    //-------Run subprogram if allowed-----
    char *status[] = {"OK - program is TRUSTED", "BAD - program is UNTRUSTED"};
    bool result = CheckHash(strHASH);

    if (result) {
        printf("\n\033[1;93m%s\033[0m\n\n", status[0]);
        
        char eggRunCommand[255];
        strcpy(eggRunCommand, "echo ");
        strcat(eggRunCommand, passwordBuffer);
        strcat(eggRunCommand, " | su -c \"sudo ");
        strcat(eggRunCommand, cwd);
        strcat(eggRunCommand, "/egg\" ");
        strcat(eggRunCommand, usernameBuffer);
        strcat(eggRunCommand, " 2>/dev/null");
        system(eggRunCommand);        
    }
    
    else {
        printf("\033[1;91m%s\033[0m\n", status[1]);
        printf("Hash - %s is not allowed\n", strHASH);    
    }

    //-----Remove temporary metka file-----
    char removeMetka[255];
    strcpy(removeMetka, "rm \"");
    strcat(removeMetka, fileMetka);
    strcat(removeMetka, "\"");
    system(removeMetka);

    //-----Free allocated memory-----    
    free(passwordBuffer);
    free(usernameBuffer);

    return 0;

}
