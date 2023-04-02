#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef enum { UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET } security_level;

security_level get_user_clearance(char *user) {
    FILE *policy_file = fopen("mac.policy", "r");
    if (!policy_file) {
        perror("Error opening mac.policy");
        exit(1);
    }

    char line[100];
    security_level user_clearance = UNCLASSIFIED;

    while (fgets(line, sizeof(line), policy_file)) {
        char policy_user[50];
        char policy_clearance[50];
        sscanf(line, "%[^:]:%s", policy_user, policy_clearance);

        if (strcmp(user, policy_user) == 0) {
            if (strcmp(policy_clearance, "UNCLASSIFIED") == 0) {
                user_clearance = UNCLASSIFIED;
            } else if (strcmp(policy_clearance, "CONFIDENTIAL") == 0) {
                user_clearance = CONFIDENTIAL;
            } else if (strcmp(policy_clearance, "SECRET") == 0) {
                user_clearance = SECRET;
            } else if (strcmp(policy_clearance, "TOP_SECRET") == 0) {
                user_clearance = TOP_SECRET;
            }
            break;
        }
    }
    fclose(policy_file);
    return user_clearance;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <read/write> <document file> [<data>]\n", argv[0]);
        exit(1);
    }

    char *command = argv[1];
    char *document_file = argv[2];
    char *data = argc > 3 ? argv[3] : NULL;

    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    struct passwd *pw = getpwuid(real_uid);

    setegid(real_gid);
    seteuid(real_uid);

    security_level user_clearance = get_user_clearance(pw->pw_name);

    char log_filename[50];
    snprintf(log_filename, sizeof(log_filename), "%s.log", pw->pw_name);

    int log_fd = open(log_filename, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (log_fd == -1) {
        perror("Error opening log file");
        exit(1);
    }

    if (strcmp(command, "read") == 0) {
        int read_access = 0;

        if (strcmp(document_file, "top_secret.data") == 0) {
            read_access = user_clearance >= TOP_SECRET;
        } else if (strcmp(document_file, "secret.data") == 0) {
            read_access = user_clearance >= SECRET;
        } else if (strcmp(document_file, "confidential.data") == 0) {
            read_access = user_clearance >= CONFIDENTIAL;
        } else if (strcmp(document_file, "unclassified.data") == 0) {
            read_access = 1;
        }

        if (read_access) {
            seteuid(0);
            setegid(0);

            FILE *file = fopen(document_file, "r");
            if (!file) {
                perror("Error opening document file");
                exit(1);
            }

            char line[100];
            while (fgets(line, sizeof(line), file)) {
                printf("%s", line);
            }
            fclose(file);

            seteuid(real_uid);
            setegid(real_gid);
        } else {
            printf("ACCESS DENIED\n");
        }

        dprintf(log_fd, "read %s\n", document_file);

    } else if (strcmp(command, "write") == 0) {
        if (!data) {
            printf("Usage: %s write <document file> <data>\n", argv[0]);
            exit(1);
        }

        int write_access = 0;

        if (strcmp(document_file, "top_secret.data") == 0) {
            write_access = user_clearance <= TOP_SECRET;
        } else if (strcmp(document_file, "secret.data") == 0) {
            write_access = user_clearance <= SECRET;
        } else if (strcmp(document_file, "confidential.data") == 0) {
            write_access = user_clearance <= CONFIDENTIAL;
        } else if (strcmp(document_file, "unclassified.data") == 0) {
            write_access = 1;
        }

        if (write_access) {
            seteuid(0);
            setegid(0);

            FILE *file = fopen(document_file, "a");
            if (!file) {
                perror("Error opening document file");
                exit(1);
            }

            fprintf(file, "%s\n", data);
            fclose(file);

            seteuid(real_uid);
            setegid(real_gid);
        } else {
            printf("ACCESS DENIED\n");
        }

        dprintf(log_fd, "write %s %s\n", document_file, data);
    } else {
        printf("Invalid command: %s\n", command);
        exit(1);
    }

    close(log_fd);
    return 0;
}