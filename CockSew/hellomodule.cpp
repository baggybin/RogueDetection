#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
//import boost library
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
using namespace std;

// funtion to return kernel high resolution clock time
// using the gettimeofday() c++ function call
// returns long integer
long get_the_time()
{
    struct timeval start;
    long mtime, seconds, useconds;    

    // use low level c call get time in seconds and microseconds
    gettimeofday(&start, NULL);
    seconds  = start.tv_sec;
    useconds = start.tv_usec;

    // convert seconds to microsecnds while adding existing miroeconds
    mtime = (seconds * 1000000) + useconds;
    return mtime;    
}

// use boost library namespace
using namespace boost::python;

// define funtion  for Python
BOOST_PYTHON_MODULE(get_the_time)
{
    def("get_the_time", get_the_time);
}


