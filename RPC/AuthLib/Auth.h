#include <cstdlib>
#include <string>
#include <functional>

namespace BH
{
	class Auth
	{
	public:
		Auth();
		~Auth();

		static unsigned int Logon(const std::wstring& userName, const std::wstring& domain, wchar_t * pass);
		static std::wstring ErrorString(unsigned int error);
	};
}