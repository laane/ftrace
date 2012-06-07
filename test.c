#include <fcntl.h>

void	toto()
{
  write(1, "boap\n", 5);
}


int main()
{
  toto();
  return 0;
}
