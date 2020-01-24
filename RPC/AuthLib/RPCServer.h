#pragma once
#include <cstdlib>
#include <string>
#include <functional>
#include "AuthError.h"
#include <future>
#include <thread>

namespace BH
{
	namespace RPC
	{
		class Server
		{
			std::atomic_bool _isListening{ false };
			std::wstring _spn;
			std::wstring _name;
			std::wstring _endpoint;
			std::wstring _pszProtocolSequence{ L"ncacn_ip_tcp" };
			unsigned int    _cMinCalls{ 1 };
			std::function<void(const std::wstring&)> _log;
			std::thread _hExec;
		public:
			/*Creates object
			name - string ID for creating SPN (Example: 'MyService'). Must be the same on client and server.
			endPoint - network port to listen.
			*/
			Server(const std::wstring& name, const std::wstring& endPoint);
			~Server();
			/*Creates thread and start listening. No blocking. 
			SuccessFullAuth will be called on successful user authentification.
			It definition must be created!
			Success - completes
			Error - throws AuthError
			*/
			void StartListen();
			//Frees resources properly
			void Stop();
			//Callback for logging. Not required.
			void SetLog(std::function<void(const std::wstring&)>);
		private:
			void Log(const wchar_t* format, ...);
			std::wstring MakeSpn(const std::wstring& name);
			void Exec(std::shared_ptr<std::promise<bool> >);
		};

		/*Will be called on successful user authentification.
		It definition must be created!
		Success - completes
		Error - throws AuthError
		*/
		void SuccessfulAuth(const std::wstring& mes);
	}
}