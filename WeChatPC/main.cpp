#include "WeChatPC.h"
#include <string>
int main()
{
	printf("%d\r\n", wcslen(LR"(WeChat.exe)"));
	WeChatPC pc;
	pc.Start();
	return 0;
}