#include <fcntl.h>

void	titi()
{
  write(1, "BOAP\n", 5);
  close(5);
}

void	toto()
{
  titi();
  write(1, "boap\n", 5);
  //  printf("Un lama... un lamaaaa sticooot!\n");
}


int main()
{
  toto();
  titi();
  return 0;
}
