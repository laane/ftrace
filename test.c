#include <fcntl.h>

void	titi()
{
  write(1, "BOAP\n", 5);
}

void	toto()
{
  titi();
  write(1, "boap\n", 5);
}


int main()
{
  toto();
  titi();
  return 0;
}
