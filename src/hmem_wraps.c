#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <io.h>
#include <stdio.h>
#include <stdarg.h>
//#include "hmem_wraps.h"

// IS_HIGH_PTR(p) is TRUE when p points to the high memory.
#ifndef IS_HIGH_PTR
#define IS_HIGH_PTR(p)   ((unsigned long int)(p) >= (512*1024*1024))
#endif


int hstat(const char *path, struct stat *buf)
{
  char *low_path = IS_HIGH_PTR(path) ? strdup( path ) : (char *)path;
  int rc = stat( low_path, buf );

  if ( low_path != path )
    free( low_path );

  return rc;
}

int hunlink(const char *path)
{
  char *low_path = IS_HIGH_PTR(path) ? strdup( path ) : (char *)path;
  int rc = unlink( low_path );

  if ( low_path != path )
    free( low_path );

  return rc;
}

int hrename(const char *old, const char *new)
{
  char *low_old = IS_HIGH_PTR(old) ? strdup( old ) : (char *)old;
  char *low_new = IS_HIGH_PTR(new) ? strdup( new ) : (char *)new;
  int rc = rename( low_old, low_new );

  if ( low_old != old )
    free( low_old );
  if ( low_new != new )
    free( low_new );

  return rc;
}

FILE *hfopen(const char *filename, const char *mode)
{
  char *low_filename = IS_HIGH_PTR(filename)
                         ? strdup( filename ) : (char *)filename;
  FILE *fd = fopen( low_filename, mode);

  if ( low_filename != filename )
    free( low_filename );

  return fd;
}

int hopen(const char *path, int access, ...)
{
  int        permission;
  va_list    args;
  int        rc;
  char       *low_path = IS_HIGH_PTR(path) ? strdup( path ) : (char *)path;

  va_start( args, access );
  permission = va_arg( args, int );
  va_end( args );
  rc = open( low_path, permission );

  if ( low_path != path )
    free( low_path );

  return rc;
}

int hread(int handle, void *buffer, unsigned len)
{
  void *low_buffer = IS_HIGH_PTR(buffer) ? malloc( len ) : buffer;
  int rc = read( handle, low_buffer, len );

  if ( low_buffer != buffer )
  {
    if ( rc > 0 )
      memcpy( buffer, low_buffer, rc );
    free( low_buffer );
  }

  return rc;
}

int hwrite(int handle, void *buffer, unsigned len)
{
  void *low_buffer;
  int rc;

  if ( IS_HIGH_PTR(buffer) )
  {
    low_buffer = malloc( len );
    memcpy( low_buffer, buffer, len );
  }
  else
    low_buffer = buffer;

  rc = write( handle, low_buffer, len );

  if ( low_buffer != buffer )
    free( low_buffer );

  return rc;
}
