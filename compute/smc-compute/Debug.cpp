

#include "Debug.h"

Debug::Debug() {}

Debug::~Debug() {}


void Debug::mark()
{
	std::cerr << Debug_Ctr_++ << " ===========\n";
}


void Debug::reset_ctr()
{
	Debug_Ctr_ = 0;
}


void Debug::push_CC(void *caller_ptr)
{
	//std::cout << typeid(class_ptr).name() << "\n";
	call_stack.push_back(typeid(caller_ptr).name());
}


void Debug::push_CC(const char *caller_name_c)
{
	//std::cout << func_name << "\n";
	std::string caller_name = caller_name_c;
	call_stack.push_back(caller_name);
}


void Debug::push_CC(std::string caller_name)
{
	//std::cout << func_name << "\n";
	call_stack.push_back(caller_name);
}


void Debug::pop_CC(void *caller_ptr)
{
	//std::cout << typeid(class_ptr).name() << "\n";
	if (call_stack.back() == typeid(caller_ptr).name())
	{
		call_stack.pop_back();
	}
	else
	{
		std::cerr << "CC stack error (pop)" << typeid(caller_ptr).name() << "\n";
	}
}


void Debug::pop_CC(const char *caller_name_c)
{
	//std::cout << func_name << "\n";
	std::string caller_name = caller_name_c;

	if (call_stack.back() == caller_name)
	{
		call_stack.pop_back();
	}
	else
	{
		std::cerr << "CC stack error (pop)" << caller_name << "\n";
	}
}


void Debug::pop_CC(std::string caller_name)
{
	//std::cout << func_name << "\n";
	if (call_stack.back() == caller_name)
	{
		call_stack.pop_back();
	}
	else
	{
		std::cerr << "CC stack error (pop)" << caller_name << "\n";
	}
}




