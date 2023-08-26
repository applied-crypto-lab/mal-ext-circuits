
#ifndef DEBUG_H
#define DEBUG_H

#include <cstdlib>
#include <vector>
#include <iostream>
#include <fstream>
#include <typeinfo>
#include "ops/Open.h"

//#define COMM_COUNTER


#define show(buf, bufsize, net, id, ss)\
\
printf("\n%s: ", #buf);\
reveal(buf, bufsize, -1, net, id, ss);


#define print(var)\
\
printf("\n%s = %i\n ", #var, var);\


#define this_class typeid(this).name()


class Debug
{

public:

	Debug();
	virtual ~Debug();

	void mark();
	void reset_ctr();

	void push_CC(void *caller_ptr);
	void push_CC(const char *caller_name_c);
	void push_CC(std::string caller_name);

	void pop_CC(void *caller_ptr);
	void pop_CC(const char *caller_name_c);
	void pop_CC(std::string caller_name);

	//void getSummary();

private:

	unsigned int Debug_Ctr_ = 0;
	std::vector<std::string> call_stack;
	std::string CC_output_str;
};



#endif /* DEBUG_H */