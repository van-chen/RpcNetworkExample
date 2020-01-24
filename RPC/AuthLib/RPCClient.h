#include <cstdlib>
#include <string>
#include <functional>
#include "AuthError.h"

namespace BH
{
	namespace RPC
	{
		class Client
		{
			bool _isStarted{ false };
			std::wstring _spn;
			std::wstring _name;
			std::wstring _endpoint;
			std::wstring _pszProtocolSequence{ L"ncacn_ip_tcp" };
			std::wstring _pszNetworkAddress;
			wchar_t* _pszStringBinding{ nullptr };
			std::function<void(const std::wstring&)> _log;
		public:
			/*Creates object
			name - string ID for creating SPN (Example: 'MyService'). Must be the same on client and server.
			networkAddres - IP address
			endPoint - network port which server is listening.
			*/
			Client(const std::wstring& name, const std::wstring& networkAddress, const std::wstring& endPoint);
			~Client();
			/*Creates binding to server
			Success - completes
			Error - throws AuthError
			*/
			void Connect();
			//Frees resources properly
			void Stop();
			//Callback for logging. Not required.
			void SetLog(std::function<void(const std::wstring&)>);
			/*Makes authentification of current process user on server and sends mes to server.
			true on success
			false on error
			throws AuthError only if called before Connect
			*/
			bool Auth(const std::wstring& mes);
		private:
			void Log(const wchar_t* format, ...);
			std::wstring MakeSpn(const std::wstring& name);
		};
	}
}