
int WriteLine(int fd, char *local, char *def);

int ReadLine(int fd, char *buf, int len);

int WriteNewLine(int fd);

int enterastring(int fd, char *locmsg, char *defmsg, char *key, int *len, int mode, int echo);

void message(int fd, char *buf, const char *format,...);
