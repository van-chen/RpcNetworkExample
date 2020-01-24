#include <string>

namespace BH
{
	class AuthError
	{
		std::wstring _errorText;
	public:
		AuthError(const std::wstring& text, unsigned int code);
		AuthError(const std::wstring& text);
		AuthError(unsigned int code);
		~AuthError();
		const wchar_t* What();
	};

}