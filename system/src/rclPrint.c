#include "tcpSvr.h"

/* Check the printing flag if it's set */
BOOL isPrintFlagSet( void )
{
	pin_mailer_t *pm = &phsmShm->pm;
	return pm->print_flag == 1;
}
