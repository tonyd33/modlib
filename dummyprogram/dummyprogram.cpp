#include <Windows.h>
#include <iostream>


int main()
{
    bool stopped = false;
    unsigned i = 10;
    while (!stopped)
    {
        // dummy instructions, hopefully it doesn't get optimized away
        i++; i--; i++; i--; i++; i--; i++; i--; i++; i--;
        stopped = false;
        i++; i--; i++; i--; i++; i--; i++; i--; i++; i--;
        Sleep(1000);
    }
    std::cout << "How'd I get stopped? 0_____0\n";
}

