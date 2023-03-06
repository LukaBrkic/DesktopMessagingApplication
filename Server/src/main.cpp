#include "../inc/Server.h"

static constexpr int PORT = 1325;

int main()
{
    Server s(PORT);
    s.start();
    return 0;
}