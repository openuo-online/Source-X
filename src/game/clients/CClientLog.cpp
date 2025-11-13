// Login and low level stuff for the client.

#include "../../common/crypto/CCrypto.h"
#include "../../common/crypto/CHuffman.h"
#include "../../common/sphere_library/CSFileList.h"
#include "../../common/sphere_library/sstringobjs.h"
#include "../../common/CLog.h"
#include "../../common/CException.h"
#include "../../common/CExpression.h"
#include "../../common/sphereversion.h"
#include "../../network/CIPHistoryManager.h"
#include "../../network/CNetworkManager.h"
#include "../../network/send.h"
#include "../CServer.h"
#include "../CWorld.h"
#include "../CWorldGameTime.h"
#include "CClient.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace zlib {
#include <zlib/zlib.h>
}

namespace
{
    constexpr lpctstr kWebAdminPrefix = "/admin/api/";

    class WebAdminConsoleCapture : public CTextConsole
    {
    public:
        mutable CSString m_Buffer;

        virtual PLEVEL_TYPE GetPrivLevel() const override
        {
            return PLEVEL_Owner;
        }

        virtual lpctstr GetName() const override
        {
            return "WebAdmin";
        }

        virtual void SysMessage(lpctstr pszMessage) const override
        {
            if (!pszMessage)
                return;

            auto* self = const_cast<WebAdminConsoleCapture*>(this);
            self->m_Buffer += pszMessage;

            const size_t len = strlen(pszMessage);
            if (len == 0 || pszMessage[len - 1] != '\n')
                self->m_Buffer += '\n';
        }
    };

    const char* WebAdminServerModeName(SERVMODE_TYPE mode) noexcept
    {
        switch (mode)
        {
            case SERVMODE_Run: return "run";
            case SERVMODE_Saving: return "saving";
            case SERVMODE_Loading: return "loading";
            case SERVMODE_ResyncLoad: return "resyncload";
            case SERVMODE_RestockAll: return "restock";
            case SERVMODE_GarbageCollection: return "garbage";
            case SERVMODE_ResyncPause: return "resyncpause";
            case SERVMODE_PreLoadingINI: return "preloading";
            case SERVMODE_Exiting: return "exiting";
            default: break;
        }
        return "unknown";
    }

    CSString WebAdminJsonEscape(lpctstr text)
    {
        CSString out;
        if (!text)
            return out;

        for (const tchar* it = text; *it != '\0'; ++it)
        {
            const unsigned char ch = static_cast<unsigned char>(*it);
            switch (*it)
            {
                case '\\': out += "\\\\"; break;
                case '"': out += "\\\""; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                {
                    if (ch < 0x20)
                    {
                        tchar buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", ch);
                        out += buf;
                    }
                    else
                    {
                        out += *it;
                    }
                    break;
                }
            }
        }
        return out;
    }

    CSString WebAdminJsonQuote(lpctstr text)
    {
        CSString quoted;
        quoted += '"';
        quoted += WebAdminJsonEscape(text);
        quoted += '"';
        return quoted;
    }

    CSString WebAdminUrlDecode(lpctstr text)
    {
        CSString out;
        if (!text)
            return out;

        for (size_t i = 0; text[i] != '\0'; ++i)
        {
            const tchar ch = text[i];
            if (ch == '+')
            {
                out += ' ';
            }
            else if (ch == '%' && text[i + 1] && text[i + 2] && std::isxdigit(static_cast<unsigned char>(text[i + 1])) && std::isxdigit(static_cast<unsigned char>(text[i + 2])))
            {
                tchar hex[3];
                hex[0] = text[i + 1];
                hex[1] = text[i + 2];
                hex[2] = '\0';
                const int val = static_cast<int>(strtol(hex, nullptr, 16));
                out += static_cast<tchar>(val);
                i += 2;
            }
            else
            {
                out += ch;
            }
        }
        return out;
    }

    bool WebAdminGetParam(lpctstr data, lpctstr name, CSString& out)
    {
        if (!data || !*data || !name || !*name)
            return false;

        TemporaryString buffer(data);
        tchar* raw = buffer.buffer();
        if (!raw)
            return false;

        tchar* tokens[64];
        const int count = Str_ParseCmds(raw, tokens, ARRAY_COUNT(tokens), "&");
        if (count <= 0)
            return false;

        const size_t nameLen = strlen(name);
        for (int i = 0; i < count; ++i)
        {
            tchar* entry = tokens[i];
            if (!entry)
                continue;

            entry = Str_TrimWhitespace(entry);
            if (*entry == '\0')
                continue;

            if (strnicmp(entry, name, nameLen) != 0)
                continue;

            tchar* value = entry + nameLen;
            if (*value == '=')
            {
                ++value;
            }
            else if (*value != '\0')
            {
                continue;
            }

            out = WebAdminUrlDecode(value);
            return true;
        }

        return false;
    }

    CSString WebAdminExtractBearerToken(lpctstr header)
    {
        CSString token;
        if (!header)
            return token;

        TemporaryString copy(header);
        tchar* value = Str_TrimWhitespace(copy.buffer());
        if (!value || *value == '\0')
            return token;

        for (tchar* p = value; *p != '\0'; ++p)
        {
            if (*p == '\r' || *p == '\n')
            {
                *p = '\0';
                break;
            }
        }

        while (*value == ':' || *value == ';')
        {
            ++value;
            GETNONWHITESPACE(value);
        }

        if (!strnicmp(value, "Bearer", 6))
        {
            value += 6;
            GETNONWHITESPACE(value);
        }

        tchar* tail = value + strlen(value);
        while (tail > value && std::isspace(static_cast<unsigned char>(tail[-1])))
        {
            --tail;
            *tail = '\0';
        }

        token = value;
        return token;
    }

    bool WebAdminParseBool(const CSString& value)
    {
        if (value.IsEmpty())
            return false;

        const lpctstr psz = value.GetBuffer();
        if (!strcmpi(psz, "1") || !strcmpi(psz, "true") || !strcmpi(psz, "yes") || !strcmpi(psz, "on"))
            return true;
        if (!strcmpi(psz, "0") || !strcmpi(psz, "false") || !strcmpi(psz, "no") || !strcmpi(psz, "off"))
            return false;
        return false;
    }

    bool WebAdminIsIpAllowed(const CSocketAddressIP& addr)
    {
        if (g_Cfg.m_sWebAdminAllowedIPs.IsEmpty())
            return addr.IsLocalAddr();

        TemporaryString buffer(g_Cfg.m_sWebAdminAllowedIPs.GetBuffer());
        tchar* raw = buffer.buffer();
        if (!raw)
            return addr.IsLocalAddr();

        tchar* entries[64];
        const int count = Str_ParseCmds(raw, entries, ARRAY_COUNT(entries), ",");
        if (count <= 0)
            return addr.IsLocalAddr();

        const CSString ip(addr.GetAddrStr());
        for (int i = 0; i < count; ++i)
        {
            tchar* entry = entries[i];
            if (!entry)
                continue;

            entry = Str_TrimWhitespace(entry);
            if (*entry == '\0')
                continue;

            if (*entry == '*')
                return true;

            if (!strnicmp(entry, "local", 5) || !strnicmp(entry, "localhost", 9))
            {
                if (addr.IsLocalAddr())
                    return true;
                continue;
            }

            if (!ip.IsEmpty() && (ip.CompareNoCase(entry) == 0))
                return true;
        }

        return false;
    }

    void WebAdminSendJsonResponse(CClient* client, int statusCode, lpctstr statusText, const CSString& body)
    {
        const CSTime now = CSTime::GetCurrentTime();
        const char* dateStr = now.FormatGmt(nullptr);

        CSString header;
        header.Format(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Server: " SPHERE_TITLE " " SPHERE_BUILD_NAME_VER_PREFIX SPHERE_BUILD_INFO_STR "\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n",
            statusCode, statusText, dateStr, body.GetLength());

        CSString response = header;
        response += body;

        PacketWeb packet;
        packet.setData(reinterpret_cast<const byte*>(response.GetBuffer()), static_cast<uint>(response.GetLength()));
        packet.send(client);
    }

    void WebAdminSendError(CClient* client, int statusCode, lpctstr statusText, lpctstr code, lpctstr message)
    {
        CSString body = "{\"status\":\"error\"";
        if (code && *code)
        {
            body += ",\"code\":";
            body += WebAdminJsonQuote(code);
        }
        if (message && *message)
        {
            body += ",\"message\":";
            body += WebAdminJsonQuote(message);
        }
        body += "}";
        WebAdminSendJsonResponse(client, statusCode, statusText, body);
    }

    bool WebAdminPerformSave(bool includeStatics, CSString& error)
    {
        if (g_World.IsSaving())
        {
            error = "A world save is already running.";
            return false;
        }

        if (!g_World.Save(true))
        {
            error = "Unable to save the world state.";
            return false;
        }

        if (includeStatics)
            g_World.SaveStatics();

        return true;
    }

    CSString WebAdminRunConsoleCommand(const CSString& command)
    {
        WebAdminConsoleCapture capture;
        CSString cmdText = command;
        g_Serv.OnConsoleCmd(cmdText, &capture);

        if (capture.m_Buffer.IsEmpty())
            capture.m_Buffer = "Command executed.";
        return capture.m_Buffer;
    }

    bool WebAdminHandleRequest(CClient* client, lpctstr method, lpctstr target, lpctstr body, size_t bodyLen, lpctstr authHeader)
    {
        if (!g_Cfg.m_fWebAdminEnable || !client || !method || !target)
            return false;

        TemporaryString mutableTarget(target);
        tchar* requestLine = mutableTarget.buffer();
        if (!requestLine)
            return false;

        requestLine = Str_TrimWhitespace(requestLine);
        if (!requestLine || *requestLine == '\0')
            return false;

        tchar* query = strchr(requestLine, '?');
        if (query)
        {
            *query = '\0';
            ++query;
        }

        const size_t prefixLen = strlen(kWebAdminPrefix);
        if (strnicmp(requestLine, kWebAdminPrefix, prefixLen) != 0)
            return false;

        tchar* routePtr = requestLine + prefixLen;
        while (*routePtr == '/')
            ++routePtr;

        if (*routePtr == '\0')
        {
            WebAdminSendError(client, 404, "Not Found", "unknown_endpoint", "Missing admin API route.");
            return true;
        }

        tchar* extra = strchr(routePtr, '/');
        if (extra)
            *extra = '\0';

        // trim trailing slash if present
        const size_t routeLen = strlen(routePtr);
        if (routeLen > 0 && routePtr[routeLen - 1] == '/')
            routePtr[routeLen - 1] = '\0';

        CSString route(routePtr);
        route.MakeLower();

        CSString queryStr = query ? query : "";
        CSString bodyStr;
        if (body && bodyLen > 0)
            bodyStr = CSString(body, static_cast<int>(bodyLen));
        else if (body)
            bodyStr = body;

        CSString token;
        if (authHeader && *authHeader)
            token = WebAdminExtractBearerToken(authHeader);
        if (token.IsEmpty())
        {
            WebAdminGetParam(queryStr.GetBuffer(), "token", token) || WebAdminGetParam(bodyStr.GetBuffer(), "token", token);
        }

        if (!WebAdminIsIpAllowed(client->GetPeer()))
        {
            WebAdminSendError(client, 403, "Forbidden", "ip_not_allowed", "This address is not allowed to call the admin API.");
            return true;
        }

        if (!g_Cfg.m_sWebAdminToken.IsEmpty())
        {
            if (token.IsEmpty() || token.CompareNoCase(g_Cfg.m_sWebAdminToken.GetBuffer()) != 0)
            {
                g_Log.Event(LOGM_HTTP | LOGL_WARN, "%x:WebAdmin invalid token from %s, received='%s' (len=%d), expected='%s' (len=%d)\n",
                    client->GetSocketID(), client->GetPeerStr(), token.GetBuffer(), token.GetLength(), g_Cfg.m_sWebAdminToken.GetBuffer(), g_Cfg.m_sWebAdminToken.GetLength());
                WebAdminSendError(client, 401, "Unauthorized", "invalid_token", "Provide a valid bearer token.");
                return true;
            }
        }

        auto logAction = [&](lpctstr action)
        {
            g_Log.Event(LOGM_HTTP | LOGL_EVENT, "%x:WebAdmin %s request '%s' from %s\n", client->GetSocketID(), action, route.GetBuffer(), client->GetPeerStr());
        };

        if (route.CompareNoCase("status") == 0 || route.CompareNoCase("health") == 0)
        {
            if (strnicmp(method, "GET", 3) != 0)
            {
                WebAdminSendError(client, 405, "Method Not Allowed", "method_not_allowed", "Use GET for this endpoint.");
                return true;
            }

            logAction("status");

            const llong uptimeSec = std::max<llong>(0, CWorldGameTime::GetCurrentTime().GetTimeDiff(g_World._iTimeStartup) / MSECS_PER_SEC);
            const SERVMODE_TYPE mode = g_Serv.GetServerMode();
            const size_t clients = g_Serv.StatGet(SERV_STAT_CLIENTS);
            const size_t items = g_Serv.StatGet(SERV_STAT_ITEMS);
            const size_t chars = g_Serv.StatGet(SERV_STAT_CHARS);

            CSString bodyJson;
            bodyJson.Format(
                "{\"status\":\"ok\",\"clients\":%" PRIuSIZE_T ",\"items\":%" PRIuSIZE_T ",\"chars\":%" PRIuSIZE_T ",\"uptime_sec\":%" PRId64 ",\"server_mode\":\"%s\",\"is_saving\":%s,\"resync_pause\":%s,\"exit_flag\":%d",
                clients,
                items,
                chars,
                uptimeSec,
                WebAdminServerModeName(mode),
                g_World.IsSaving() ? "true" : "false",
                g_Serv.m_fResyncPause ? "true" : "false",
                g_Serv.GetExitFlag());

            if (g_Serv.m_timeShutdown > 0)
            {
                CSString extraField;
                extraField.Format(",\"scheduled_shutdown\":%" PRIi64, g_Serv.m_timeShutdown);
                bodyJson += extraField;
            }

            bodyJson += "}";
            WebAdminSendJsonResponse(client, 200, "OK", bodyJson);
            return true;
        }

        if (route.CompareNoCase("command") == 0)
        {
            if (strnicmp(method, "POST", 4) != 0)
            {
                WebAdminSendError(client, 405, "Method Not Allowed", "method_not_allowed", "Use POST for this endpoint.");
                return true;
            }

            CSString cmd;
            if (!WebAdminGetParam(bodyStr.GetBuffer(), "cmd", cmd))
                WebAdminGetParam(queryStr.GetBuffer(), "cmd", cmd);

            if (cmd.IsEmpty())
            {
                WebAdminSendError(client, 400, "Bad Request", "missing_cmd", "Provide the cmd parameter.");
                return true;
            }

            logAction("command");

            const CSString output = WebAdminRunConsoleCommand(cmd);
            CSString bodyJson = "{\"status\":\"ok\",\"command\":";
            bodyJson += WebAdminJsonQuote(cmd.GetBuffer());
            bodyJson += ",\"output\":";
            bodyJson += WebAdminJsonQuote(output.GetBuffer());
            bodyJson += "}";
            WebAdminSendJsonResponse(client, 200, "OK", bodyJson);
            return true;
        }

        if (route.CompareNoCase("save") == 0)
        {
            if (strnicmp(method, "POST", 4) != 0)
            {
                WebAdminSendError(client, 405, "Method Not Allowed", "method_not_allowed", "Use POST for this endpoint.");
                return true;
            }

            CSString staticsValue;
            bool includeStatics = false;
            if (WebAdminGetParam(bodyStr.GetBuffer(), "statics", staticsValue) || WebAdminGetParam(queryStr.GetBuffer(), "statics", staticsValue))
                includeStatics = WebAdminParseBool(staticsValue);

            CSString error;
            if (!WebAdminPerformSave(includeStatics, error))
            {
                WebAdminSendError(client, 409, "Conflict", "save_in_progress", error.GetBuffer());
                return true;
            }

            logAction("save");

            CSString bodyJson;
            bodyJson.Format("{\"status\":\"ok\",\"action\":\"save\",\"statics\":%s}", includeStatics ? "true" : "false");
            WebAdminSendJsonResponse(client, 200, "OK", bodyJson);
            return true;
        }

        if (route.CompareNoCase("restart") == 0 || route.CompareNoCase("shutdown") == 0)
        {
            if (strnicmp(method, "POST", 4) != 0)
            {
                WebAdminSendError(client, 405, "Method Not Allowed", "method_not_allowed", "Use POST for this endpoint.");
                return true;
            }

            if (g_Serv.GetExitFlag() != 0)
            {
                WebAdminSendError(client, 409, "Conflict", "shutdown_pending", "Server shutdown is already pending.");
                return true;
            }

            CSString staticsValue;
            bool includeStatics = false;
            if (WebAdminGetParam(bodyStr.GetBuffer(), "statics", staticsValue) || WebAdminGetParam(queryStr.GetBuffer(), "statics", staticsValue))
                includeStatics = WebAdminParseBool(staticsValue);

            CSString error;
            if (!WebAdminPerformSave(includeStatics, error))
            {
                WebAdminSendError(client, 409, "Conflict", "save_failed", error.GetBuffer());
                return true;
            }

            const bool isRestart = (route.CompareNoCase("restart") == 0);
            logAction(isRestart ? "restart" : "shutdown");

            CSString bodyJson;
            bodyJson.Format("{\"status\":\"ok\",\"action\":\"%s\",\"statics\":%s,\"exit_flag\":2}", route.GetBuffer(), includeStatics ? "true" : "false");
            WebAdminSendJsonResponse(client, 200, "OK", bodyJson);

            g_Serv.SetExitFlag(2);
            return true;
        }

        WebAdminSendError(client, 404, "Not Found", "unknown_endpoint", "Unknown admin API path.");
        return true;
    }
}

/////////////////////////////////////////////////////////////////
// -CClient stuff.

uint CClient::xCompress( byte * pOutput, const byte * pInput, uint outLen, uint inLen ) // static
{
	ADDTOCALLSTACK("CClient::xCompress");
	// The game server will compress the outgoing data to the clients.
	return CHuffman::Compress( pOutput, pInput, outLen, inLen );
}

bool CClient::IsConnecting() const
{
	ADDTOCALLSTACK("CClient::IsConnecting");
	switch ( GetConnectType() )
	{
		case CONNECT_TELNET:
		case CONNECT_AXIS:
		case CONNECT_HTTP:
		case CONNECT_GAME:
			return false;

		default:
			return true;
	}
}

lpctstr CClient::GetConnectTypeStr(CONNECT_TYPE iType)
{
	switch (iType)
	{
		case CONNECT_NONE:		return "No connection";
		case CONNECT_UNK:		return "Just connected";
		case CONNECT_CRYPT:		return "ServerList or CharList?";
		case CONNECT_LOGIN:		return "ServerList";
		case CONNECT_GAME:		return "CharList/Game";
		case CONNECT_HTTP:		return "HTTP";
		case CONNECT_TELNET:	return "Telnet";
		case CONNECT_UOG:		return "UOG";
		case CONNECT_AXIS:		return "Axis";
		default:				return "Unknown";
	}
}

void CClient::SetConnectType( CONNECT_TYPE iType )
{
	ADDTOCALLSTACK("CClient::SetConnectType");

    auto _IsFullyConnectedType = [](const CONNECT_TYPE typ) noexcept -> bool {
        switch (typ)
        {
        case CONNECT_GAME:
        case CONNECT_HTTP:
        case CONNECT_TELNET:
        case CONNECT_UOG:
        case CONNECT_AXIS:
            return true;
        default:
            return false;
        }
    };

	if (_IsFullyConnectedType(iType) && !_IsFullyConnectedType(m_iConnectType))
	{
		HistoryIP& history = g_NetworkManager.getIPHistoryManager().getHistoryForIP(GetPeer());
		-- history.m_iPendingConnectionRequests;
	}
	m_iConnectType = iType;

/*
	m_iConnectType = iType;
	if ( iType == CONNECT_GAME )
	{
		HistoryIP& history = g_NetworkManager.getIPHistoryManager().getHistoryForIP(GetPeer());
		-- history.m_connecting;
	}
*/
}

//---------------------------------------------------------------------
// Push world display data to this client only.

bool CClient::addLoginErr(byte code)
{
	ADDTOCALLSTACK("CClient::addLoginErr");
	// code
	// 0 = no account
	// 1 = account used.
	// 2 = blocked.
	// 3 = no password
	// LOGIN_ERR_OTHER

	if (code == PacketLoginError::Success)
		return true;

	// console message to display for each login error code
	static lpctstr constexpr sm_Login_ErrMsg[] =
	{
		"Account does not exist",
		"The account entered is already being used",
		"This account or IP is blocked",
		"The password entered is not correct",
		"Timeout / Wrong encryption / Unknown error",
		"Invalid client version. See the CLIENTVERSION setting in " SPHERE_FILE ".ini",
		"Invalid character selected (chosen character does not exist)",
		"AuthID is not correct. This normally means that the client did not log in via the login server",
		"The account details entered are invalid (username or password is too short, too long or contains invalid characters). This can sometimes be caused by incorrect/missing encryption keys",
		"The account details entered are invalid (username or password is too short, too long or contains invalid characters). This can sometimes be caused by incorrect/missing encryption keys",
		"Encryption error: packet length does not match what was expected",
		"Encryption error: bad login packet or unknown encryption (encryption key missing in " SPHERE_FILE "Crypt.ini?)",
		"Encrypted client not permitted. See the USECRYPT setting in " SPHERE_FILE ".ini",
		"Unencrypted client not permitted. See the USENOCRYPT setting in " SPHERE_FILE ".ini",
		"Another character on this account is already ingame",
		"Account is full. Cannot create a new character",
		"Character creation blocked.",
		"This IP is blocked",
		"The maximum number of clients has been reached. See the CLIENTMAX setting in " SPHERE_FILE ".ini",
		"The maximum number of guests has been reached. See the GUESTSMAX setting in " SPHERE_FILE ".ini",
		"The maximum number of password tries has been reached"
	};

	if (code >= ARRAY_COUNT(sm_Login_ErrMsg))
		code = PacketLoginError::Other;

	g_Log.EventWarn( "%x:Bad Login %d. %s.\n", GetSocketID(), code, sm_Login_ErrMsg[(size_t)code] );

	// translate the code into a code the client will understand
	switch (code)
	{
		case PacketLoginError::Invalid:
			code = PacketLoginError::Invalid;
			break;
		case PacketLoginError::InUse:
		case PacketLoginError::CharIdle:
			code = PacketLoginError::InUse;
			break;
		case PacketLoginError::Blocked:
		case PacketLoginError::BlockedIP:
		case PacketLoginError::MaxClients:
		case PacketLoginError::MaxGuests:
			code = PacketLoginError::Blocked;
			break;
		case PacketLoginError::BadPass:
		case PacketLoginError::BadAccount:
		case PacketLoginError::BadPassword:
			code = PacketLoginError::BadPass;
			break;
		case PacketLoginError::Other:
		case PacketLoginError::BadVersion:
		case PacketLoginError::BadCharacter:
		case PacketLoginError::BadAuthID:
		case PacketLoginError::BadEncLength:
		case PacketLoginError::EncCrypt:
		case PacketLoginError::EncNoCrypt:
		case PacketLoginError::TooManyChars:
		case PacketLoginError::MaxPassTries:
		case PacketLoginError::EncUnknown:
		default:
			code = PacketLoginError::Other;
			break;
	}

	if ( GetNetState()->m_clientVersionNumber || GetNetState()->m_reportedVersionNumber )	// only reply the packet to valid clients
		new PacketLoginError(this, static_cast<PacketLoginError::Reason>(code));
	GetNetState()->markReadClosed();
	return false;
}


void CClient::addSysMessage(lpctstr pszMsg) // System message (In lower left corner)
{
	ADDTOCALLSTACK("CClient::addSysMessage");
	if ( !pszMsg )
		return;

	if ( IsSetOF(OF_Flood_Protection) && ( GetPrivLevel() <= PLEVEL_Player )  )
	{
		if ( !strnicmp(pszMsg, m_zLastMessage, SCRIPT_MAX_LINE_LEN) )
			return;

		Str_CopyLimitNull(m_zLastMessage, pszMsg, SCRIPT_MAX_LINE_LEN);
	}

	addBarkParse(pszMsg, nullptr, HUE_TEXT_DEF, TALKMODE_SAY);
}


void CClient::addWebLaunch( lpctstr pPage )
{
	ADDTOCALLSTACK("CClient::addWebLaunch");
	// Direct client to a web page
	if ( !pPage || !pPage[0] )
		return;
	SysMessageDefault(DEFMSG_WEB_BROWSER_START);
	new PacketWebPage(this, pPage);
}

///////////////////////////////////////////////////////////////
// Login server.

bool CClient::addRelay( const CServerDef * pServ )
{
	ADDTOCALLSTACK("CClient::addRelay");
	EXC_TRY("addRelay");

	// Tell the client to play on this server.
	if ( !pServ )
		return false;

	CSocketAddressIP ipAddr = pServ->m_ip;

	if ( ipAddr.IsLocalAddr())	// local server address not yet filled in.
	{
		ipAddr.SetAddrIP(m_net->m_socket.GetSockName().GetAddrIP());
		DEBUG_MSG(( "%x:Login_Relay to %s\n", GetSocketID(), ipAddr.GetAddrStr() ));
	}

	if ( GetPeer().IsLocalAddr() || GetPeer().IsSameIP( ipAddr ))	// weird problem with client relaying back to self.
	{
		DEBUG_MSG(( "%x:Login_Relay loopback to server %s\n", GetSocketID(), ipAddr.GetAddrStr() ));
		ipAddr.SetAddrIP( SOCKET_LOCAL_ADDRESS );
	}

	EXC_SET_BLOCK("customer id");
	dword dwAddr = ipAddr.GetAddrIP();
	dword dwCustomerId = 0x7f000001;
	if ( g_Cfg.m_fUseAuthID )
	{
		CSString sCustomerID(pServ->GetName());
		sCustomerID.Add(GetAccount()->GetName());

		dwCustomerId = zlib::crc32(0L, nullptr, 0);
		dwCustomerId = zlib::crc32(dwCustomerId, reinterpret_cast<const zlib::Bytef *>(sCustomerID.GetBuffer()), (zlib::uInt)sCustomerID.GetLength());

		GetAccount()->m_TagDefs.SetNum("customerid", dwCustomerId);
	}

	DEBUG_MSG(( "%x:Login_Relay to server %s with AuthId %u\n", GetSocketID(), ipAddr.GetAddrStr(), dwCustomerId ));

	EXC_SET_BLOCK("server relay packet");
	new PacketServerRelay(this, dwAddr, pServ->m_ip.GetPort(), dwCustomerId);

	m_Targ_Mode = CLIMODE_SETUP_RELAY;
	return true;
	EXC_CATCH;

	EXC_DEBUG_START;
	g_Log.EventDebug("account '%s'\n", GetAccount() ? GetAccount()->GetName() : "");
	EXC_DEBUG_END;
	return false;
}

bool CClient::Login_Relay( uint iRelay ) // Relay player to a selected IP
{
	ADDTOCALLSTACK("CClient::Login_Relay");
	// Client wants to be relayed to another server. XCMD_ServerSelect
	// iRelay = 0 = this local server.

	// Sometimes we get an extra 0x80 ???
	if ( iRelay >= 0x80 )
	{
		iRelay -= 0x80;
	}

	// >= 1.26.00 clients list Gives us a 1 based index for some reason.
	if ( iRelay > 0 )
		-- iRelay;

	CServerRef pServ;
	if ( iRelay <= 0 )
	{
		pServ = &g_Serv;	// we always list ourself first.
	}
	else
	{
		iRelay --;
		pServ = g_Cfg.Server_GetDef(iRelay);
		if ( pServ == nullptr )
		{
			DEBUG_ERR(( "%x:Login_Relay BAD index! %u\n", GetSocketID(), iRelay ));
			return false;
		}
	}

	return addRelay( pServ );
}

byte CClient::Login_ServerList( const char * pszAccount, const char * pszPassword )
{
	ADDTOCALLSTACK("CClient::Login_ServerList");
	// XCMD_ServersReq
	// Initial login (Login on "loginserver", new format)
	// If the messages are garbled make sure they are terminated to correct length.

	tchar szAccount[MAX_ACCOUNT_NAME_SIZE+3];
	size_t iLenAccount = Str_GetBare( szAccount, pszAccount, sizeof(szAccount)-1 );
	if ( iLenAccount > MAX_ACCOUNT_NAME_SIZE )
		return( PacketLoginError::BadAccount );
	if ( iLenAccount != strlen(pszAccount))
		return( PacketLoginError::BadAccount );

	tchar szPassword[MAX_NAME_SIZE+3];
	size_t iLenPassword = Str_GetBare( szPassword, pszPassword, sizeof( szPassword )-1 );
	if ( iLenPassword > MAX_NAME_SIZE )
		return( PacketLoginError::BadPassword );
	if ( iLenPassword != strlen(pszPassword))
		return( PacketLoginError::BadPassword );

	// don't bother logging in yet.
	// Give the server list to everyone.
	// if ( LogIn( pszAccount, pszPassword ) )
	//   return( PacketLoginError::BadPass );
	CSString sMsg;
	byte lErr = LogIn( pszAccount, pszPassword, sMsg );
	if ( lErr != PacketLoginError::Success )
	{
		return( lErr );
	}

	new PacketServerList(this);

	m_Targ_Mode = CLIMODE_SETUP_SERVERS;
	return( PacketLoginError::Success );
}

//*****************************************

bool CClient::OnRxConsoleLoginComplete()
{
	ADDTOCALLSTACK("CClient::OnRxConsoleLoginComplete");
	if ( GetConnectType() != CONNECT_TELNET )
		return false;
	if ( !GetPeer().IsValidAddr() )
		return false;

	if ( GetPrivLevel() < PLEVEL_Admin )	// this really should not happen.
	{
		SysMessagef("%s\n", g_Cfg.GetDefaultMsg(DEFMSG_CONSOLE_NO_ADMIN));
		return false;
	}

	SysMessagef("%s '%s' ('%s')\n", g_Cfg.GetDefaultMsg(DEFMSG_CONSOLE_WELCOME_2), GetName(), GetPeerStr());
	return true;
}

bool CClient::OnRxConsole( const byte * pData, uint iLen )
{
	ADDTOCALLSTACK("CClient::OnRxConsole");
	// A special console version of the client. (Not game protocol)
	if ( !iLen || ( GetConnectType() != CONNECT_TELNET ))
		return false;

	if ( IsSetEF( EF_AllowTelnetPacketFilter ) )
	{
		bool fFiltered = xPacketFilter(pData, iLen);
		if ( fFiltered )
			return fFiltered;
	}

	while ( iLen -- )
	{
		int iRet = OnConsoleKey( m_Targ_Text, *pData++, GetAccount() != nullptr );
		if ( ! iRet )
			return false;
		if ( iRet == 2 )
		{
			if ( GetAccount() == nullptr )
			{
				if ( !m_zLogin[0] )
				{
					if ( (uint)(m_Targ_Text.GetLength()) > (sizeof(m_zLogin) - 1) )
					{
						SysMessage("Login:\n");
					}
					else
					{
						Str_CopyLimitNull(m_zLogin, m_Targ_Text, sizeof(m_zLogin));
						SysMessage("Password:\n");
					}
					m_Targ_Text.Clear();
				}
				else
				{
					CAccount * pAccount = g_Accounts.Account_Find(m_zLogin);
					if (( pAccount == nullptr ) || ( pAccount->GetPrivLevel() < PLEVEL_Admin ))
					{
						SysMessagef("%s\n", g_Cfg.GetDefaultMsg(DEFMSG_CONSOLE_NOT_PRIV));
						m_Targ_Text.Clear();
						return false;
					}

					CSString sMsg;
					if ( LogIn(m_zLogin, m_Targ_Text, sMsg ) == PacketLoginError::Success )
					{
						m_Targ_Text.Clear();
						return OnRxConsoleLoginComplete();
					}
					else if ( ! sMsg.IsEmpty())
					{
						SysMessage( sMsg );
						return false;
					}
					m_Targ_Text.Clear();
				}
				return true;
			}
			else
			{
				iRet = g_Serv.OnConsoleCmd( m_Targ_Text, this );

				if (g_Cfg.m_fTelnetLog && GetPrivLevel() >= g_Cfg.m_iCommandLog)
					g_Log.Event(LOGM_GM_CMDS, "%x:'%s' commands '%s'=%d\n", GetSocketID(), GetName(), static_cast<lpctstr>(m_Targ_Text), iRet);
			}
		}
	}
	return true;
}

bool CClient::OnRxAxis( const byte * pData, uint iLen )
{
	ADDTOCALLSTACK("CClient::OnRxAxis");
	if ( !iLen || ( GetConnectType() != CONNECT_AXIS ))
		return false;

	while ( iLen -- )
	{
		int iRet = OnConsoleKey( m_Targ_Text, *pData++, GetAccount() != nullptr );
		if ( ! iRet )
			return false;
		if ( iRet == 2 )
		{
			if ( GetAccount() == nullptr )
			{
				if ( !m_zLogin[0] )
				{
					if ((uint)(m_Targ_Text.GetLength()) <= (sizeof(m_zLogin) - 1))
					{
						Str_CopyLimitNull(m_zLogin, m_Targ_Text, sizeof(m_zLogin));
					}
					m_Targ_Text.Clear();
				}
				else
				{
					CAccount * pAccount = g_Accounts.Account_Find(m_zLogin);
					if (( pAccount == nullptr ) || ( pAccount->GetPrivLevel() < PLEVEL_Counsel ))
					{
						SysMessagef("\"MSG:%s\"", g_Cfg.GetDefaultMsg(DEFMSG_AXIS_NOT_PRIV));
						m_Targ_Text.Clear();
						return false;
					}

					CSString sMsg;
					if ( LogIn(m_zLogin, m_Targ_Text, sMsg ) == PacketLoginError::Success )
					{
						m_Targ_Text.Clear();
						if ( GetPrivLevel() < PLEVEL_Counsel )
						{
							SysMessagef("\"MSG:%s\"", g_Cfg.GetDefaultMsg(DEFMSG_AXIS_NOT_PRIV));
							return false;
						}
						if (GetPeer().IsValidAddr())
						{
							CScriptTriggerArgs Args;
							Args.m_VarsLocal.SetStrNew("Account",GetName());
							Args.m_VarsLocal.SetStrNew("IP",GetPeer().GetAddrStr());
							TRIGRET_TYPE tRet = TRIGRET_RET_DEFAULT;
							r_Call("f_axis_preload", this, &Args, nullptr, &tRet);
							if ( tRet == TRIGRET_RET_FALSE )
								return false;
							if ( tRet == TRIGRET_RET_TRUE )
							{
								SysMessagef("\"MSG:%s\"", g_Cfg.GetDefaultMsg(DEFMSG_AXIS_DENIED));
								return false;
							}

							time_t dateChange;
							dword dwSize;
							if ( ! CSFileList::ReadFileInfo( "Axis.db", dateChange, dwSize ))
							{
								SysMessagef("\"MSG:%s\"", g_Cfg.GetDefaultMsg(DEFMSG_AXIS_INFO_ERROR));
								return false;
							}

							CSFile FileRead;
							if ( ! FileRead.Open( "Axis.db", OF_READ|OF_BINARY ))
							{
								SysMessagef("\"MSG:%s\"", g_Cfg.GetDefaultMsg(DEFMSG_AXIS_FILE_ERROR));
								return false;
							}

							tchar szTmp[8*1024];
							PacketWeb packet;
							for (;;)
							{
								int iLength = FileRead.Read( szTmp, sizeof( szTmp ) );
								if ( iLength <= 0 )
									break;
								packet.setData((byte*)szTmp, (uint)iLength);
								packet.send(this);
								dwSize -= (dword)iLength;
								if ( dwSize <= 0 )
									break;
							}
							return true;
						}
						return false;
					}
					else if ( ! sMsg.IsEmpty())
					{
						SysMessagef("\"MSG:%s\"", sMsg.GetBuffer());
						return false;
					}
					m_Targ_Text.Clear();
				}
				return true;
			}
		}
	}
	return true;
}

bool CClient::OnRxPing( const byte * pData, uint iLen )
{
	ADDTOCALLSTACK("CClient::OnRxPing");
	// packet iLen < 5
	// UOMon should work like this.
	// RETURN: true = keep the connection open.
	if ( GetConnectType() != CONNECT_UNK )
		return false;

	if ( !iLen || iLen > 4 )
		return false;

	switch ( pData[0] )
	{
		// Remote Admin Console
		case '\x1':
		case ' ':
		{
			if ( (iLen > 1) &&
				 (iLen != 2 || pData[1] != '\n') &&
				 (iLen != 3 || pData[1] != '\r' || pData[2] != '\n') &&
				 (iLen != 3 || pData[1] != '\n' || pData[2] != '\0') )
				break;

			// enter into remote admin mode. (look for password).
			SetConnectType( CONNECT_TELNET );
			m_zLogin[0] = 0;
			SysMessagef("%s %s Admin Telnet\n", g_Cfg.GetDefaultMsg(DEFMSG_CONSOLE_WELCOME_1), g_Serv.GetName());

			if ( g_Cfg.m_fLocalIPAdmin )
			{
				// don't bother logging in if local.

				if ( GetPeer().IsLocalAddr() )
				{
					CAccount * pAccount = g_Accounts.Account_Find("Administrator");
					if ( !pAccount )
						pAccount = g_Accounts.Account_Find("RemoteAdmin");
					if ( pAccount )
					{
						CSString sMsg;
						byte lErr = LogIn( pAccount, sMsg );
						if ( lErr != PacketLoginError::Success )
						{
							if ( lErr != PacketLoginError::Invalid )
								SysMessage( sMsg );
							return false;
						}
						return OnRxConsoleLoginComplete();
					}
				}
			}

			SysMessage("Login:\n");
			return true;
		}

		//Axis Connection
		case '@':
		{
			if ( (iLen > 1) &&
				 (iLen != 2 || pData[1] != '\n') &&
				 (iLen != 3 || pData[1] != '\r' || pData[2] != '\n') &&
				 (iLen != 3 || pData[1] != '\n' || pData[2] != '\0') )
				break;

			// enter into Axis mode. (look for password).
			SetConnectType( CONNECT_AXIS );
			m_zLogin[0] = 0;

			time_t dateChange;
			dword dwSize = 0;
			CSFileList::ReadFileInfo( "Axis.db", dateChange, dwSize );
			SysMessagef("%u",dwSize);
			return true;
		}

		// ConnectUO Status
		case 0xF1:
		{
			// ConnectUO sends a 4-byte packet when requesting status info
			// byte Cmd		(0xF1)
			// word Unk		(0x04)
			// byte SubCmd	(0xFF)

            if ( iLen != make_word( pData[2], pData[1] ) )
				break;

			if ( pData[3] != 0xFF )
				break;

			if ( g_Cfg.m_fCUOStatus == false )
			{
				g_Log.Event( LOGM_CLIENTS_LOG|LOGL_EVENT, "%x:CUO Status request from %s has been rejected.\n", GetSocketID(), GetPeerStr());
				return false;
			}

			// enter 'remote admin mode'
			SetConnectType( CONNECT_TELNET );

			g_Log.Event( LOGM_CLIENTS_LOG|LOGL_EVENT, "%x:CUO Status request from %s\n", GetSocketID(), GetPeerStr());

			SysMessage( g_Serv.GetStatusString( 0x25 ) );

			// exit 'remote admin mode'
			SetConnectType( CONNECT_UNK );
			return false;
		}

		// UOGateway Status
		case 0xFF:
		case 0x7F:
		case 0x22:
		{
			if ( iLen > 1 )
				break;

			if ( g_Cfg.m_fUOGStatus == false )
			{
				g_Log.Event( LOGM_CLIENTS_LOG|LOGL_EVENT, "%x:UOG Status request from %s has been rejected.\n", GetSocketID(), GetPeerStr());
				return false;
			}

			// enter 'remote admin mode'
			SetConnectType( CONNECT_TELNET );

			g_Log.Event( LOGM_CLIENTS_LOG|LOGL_EVENT, "%x:UOG Status request from %s\n", GetSocketID(), GetPeerStr());

			if (pData[0] == 0x7F)
				SetConnectType( CONNECT_UOG );

			SysMessage( g_Serv.GetStatusString( 0x22 ) );

			// exit 'remote admin mode'
			SetConnectType( CONNECT_UNK );
			return false;
		}
	}

	g_Log.Event( LOGM_CLIENTS_LOG|LOGL_EVENT, "%x:Unknown/invalid ping data '0x%x' from %s (Len: %u)\n", GetSocketID(), pData[0], GetPeerStr(), iLen);
	return false;
}

bool CClient::OnRxWebPageRequest( byte * pRequest, size_t uiLen )
{
	ADDTOCALLSTACK("CClient::OnRxWebPageRequest");

    // Seems to be a web browser pointing at us ? typical stuff :
	if ( GetConnectType() != CONNECT_HTTP )
		return false;

    const size_t uiRawRequestLen = uiLen;
	char chSavedTail = '\0';
	if (uiLen > HTTPREQ_MAX_SIZE)    // request too long
		goto httpreq_err_long;

	if (uiLen > 0)
	{
		chSavedTail = reinterpret_cast<char*>(pRequest)[uiLen - 1];
		reinterpret_cast<char*>(pRequest)[uiLen - 1] = '\0';
	}

	uiLen = strlen(reinterpret_cast<const char*>(pRequest));
    if (uiLen > HTTPREQ_MAX_SIZE)     // too long request
    {
    httpreq_err_long:
        g_Log.EventWarn("%x:Client sent HTTP request of length %" PRIuSIZE_T" exceeding max length limit of %d, ignoring.\n", GetNetState()->id(), uiLen, HTTPREQ_MAX_SIZE);
        return false;
    }

	if ( !strpbrk( reinterpret_cast<const char *>(pRequest), " \t\012\015" ) )    // malformed request
		return false;

	tchar * ppLines[16];
	int iQtyLines = Str_ParseCmds(reinterpret_cast<char *>(pRequest), ppLines, ARRAY_COUNT(ppLines), "\r\n");
	if (( iQtyLines < 1 ) || ( iQtyLines >= 15 ))	// too long request
		return false;

	// Look for what they want to do with the connection.
	bool fKeepAlive = false;
	CSTime dateIfModifiedSince;
	tchar * pszReferer = nullptr;
	CSString sAuthHeader;
	uint uiContentLength = 0;
	for ( int j = 1; j < iQtyLines; ++j )
	{
		tchar *pszArgs = Str_TrimWhitespace(ppLines[j]);
		if ( !strnicmp(pszArgs, "Connection:", 11 ) )
		{
			pszArgs += 11;
			GETNONWHITESPACE(pszArgs);
			if ( !strnicmp(pszArgs, "Keep-Alive", 10) )
				fKeepAlive = true;
		}
		else if ( !strnicmp(pszArgs, "Referer:", 8) )
		{
			pszReferer = pszArgs+8;
		}
		else if ( !strnicmp(pszArgs, "Authorization:", 13) )
		{
			pszArgs += 13;
			GETNONWHITESPACE(pszArgs);
			sAuthHeader = pszArgs;
		}
		else if ( !strnicmp(pszArgs, "Content-Length:", 15) )
		{
			pszArgs += 15;
			GETNONWHITESPACE(pszArgs);
            std::optional<uint> iconv = Str_ToU(pszArgs, 10);
            if (!iconv.has_value())
                continue;

            uiContentLength = *iconv;
		}
		else if ( ! strnicmp( pszArgs, "If-Modified-Since:", 18 ))
		{
			// If-Modified-Since: Fri, 17 Dec 1999 14:59:20 GMT\r\n
			pszArgs += 18;
			dateIfModifiedSince.Read(pszArgs);
		}
	}

	tchar * ppRequest[4];
	int iQtyArgs = Str_ParseCmds(ppLines[0], ppRequest, ARRAY_COUNT(ppRequest), " ");
	if (( iQtyArgs < 2 ) || ( strlen(ppRequest[1]) >= SPHERE_MAX_PATH ))
		return false;

	if ( strchr(ppRequest[1], '\r') || strchr(ppRequest[1], 0x0c) )
		return false;

	int iSocketRet = 0;

	// if the client hasn't requested a keep alive, we must act as if they had
	// when async networking is used, otherwise data may not be completely sent
	if ( fKeepAlive == false )
	{
		fKeepAlive = m_net->isAsyncMode();

		// must switch to a blocking socket when the connection is not being kept
		// alive, or else pending data will be lost when the socket shuts down

		if (fKeepAlive == false)
		{
			iSocketRet = m_net->m_socket.SetNonBlocking(false);
			if (iSocketRet)
				return false;
		}
	}

	linger llinger{};
	llinger.l_onoff = 1;
	llinger.l_linger = 500;	// in mSec
	iSocketRet = m_net->m_socket.SetSockOpt(SO_LINGER, reinterpret_cast<char *>(&llinger), sizeof(linger));
	CheckReportNetAPIErr(iSocketRet, "CClient::Webpage.SO_LINGER");
	if (iSocketRet)
		return false;

	int iSockFlag = 1;
	iSocketRet = m_net->m_socket.SetSockOpt(SO_KEEPALIVE, &iSockFlag, sizeof(iSockFlag));
	CheckReportNetAPIErr(iSocketRet, "CClient::Webpage.SO_KEEPALIVE");
	if (iSocketRet)
		return false;

	// disable NAGLE algorythm for data compression
	iSockFlag = 1;
	iSocketRet = m_net->m_socket.SetSockOpt(TCP_NODELAY, &iSockFlag, sizeof(iSockFlag), IPPROTO_TCP);
	CheckReportNetAPIErr(iSocketRet, "CClient::Webpage.TCP_NODELAY");
	if (iSocketRet)
		return false;

	const bool isPostRequest = (memcmp(ppLines[0], "POST", 4) == 0);
	const bool isGetRequest = (!memcmp(ppLines[0], "GET", 3));
	const tchar* postPayload = nullptr;
	size_t postPayloadLen = 0;
	CSString postPayloadStorage;
	if (isPostRequest)
	{
		if (uiContentLength > 0 && uiContentLength <= uiRawRequestLen)
		{
			postPayloadStorage.CopyLen(reinterpret_cast<char*>(pRequest) + (uiRawRequestLen - uiContentLength), static_cast<int>(uiContentLength));
			if (uiContentLength > 0)
				postPayloadStorage.SetAt(static_cast<int>(uiContentLength - 1), chSavedTail);
			postPayload = postPayloadStorage.GetBuffer();
			postPayloadLen = uiContentLength;
		}
		else
		{
			postPayload = ppLines[iQtyLines - 1];
			postPayloadLen = strlen(postPayload);
		}
	}

	lpctstr pszAuthHeader = sAuthHeader.IsEmpty() ? nullptr : sAuthHeader.GetBuffer();
	if ( WebAdminHandleRequest(this, ppRequest[0], ppRequest[1], postPayload, postPayloadLen, pszAuthHeader) )
		return false;

	if ( isPostRequest )
	{
		// POST /--WEBBOT-SELF-- HTTP/1.1
		// Referer: http://127.0.0.1:2593/spherestatus.htm
		// Content-Type: application/x-www-form-urlencoded
		// Host: 127.0.0.1:2593
		// Content-Length: 29
		// T1=stuff1&B1=Submit&T2=stuff2

		g_Log.Event(LOGM_HTTP|LOGL_EVENT, "%x:HTTP Page Post '%s'\n", GetSocketID(), static_cast<lpctstr>(ppRequest[1]));

		CWebPageDef	*pWebPage = g_Cfg.FindWebPage(ppRequest[1]);
		if ( !pWebPage )
			pWebPage = g_Cfg.FindWebPage(pszReferer);
		if ( pWebPage )
		{
			if ( pWebPage->ServPagePost(this, ppRequest[1], const_cast<tchar*>(postPayload), uiContentLength) )
			{
				if ( fKeepAlive )
					return true;
				return false;
			}
			return false;
		}
	}
	else if ( isGetRequest )
	{
		// GET /pagename.htm HTTP/1.1\r\n
		// If-Modified-Since: Fri, 17 Dec 1999 14:59:20 GMT\r\n
		// Host: localhost:2593\r\n
		// \r\n

		tchar szPageName[SPHERE_MAX_PATH];
		if ( !Str_GetBare( szPageName, Str_TrimWhitespace(ppRequest[1]), sizeof(szPageName), "!\"#$%&()*,:;<=>?[]^{|}-+'`" ) )
			return false;

		g_Log.Event(LOGM_HTTP|LOGL_EVENT, "%x:HTTP Page Request '%s', alive=%d\n", GetSocketID(), szPageName, fKeepAlive);
        CWebPageDef::ServPage(this, szPageName, &dateIfModifiedSince);
		/*if ( CWebPageDef::ServPage(this, szPageName, &dateIfModifiedSince) )
		{
			if ( fKeepAlive )
				return true;
			return false;
		}*/
	}


	return false;
}

bool CClient::xProcessClientSetup( CEvent * pEvent, uint uiLen )
{
	ADDTOCALLSTACK("CClient::xProcessClientSetup");
	// If this is a login then try to process the data and figure out what client it is.
	// try to figure out which client version we are talking to.
	// (CEvent::ServersReq) or (CEvent::CharListReq)
	// NOTE: Anything else we get at this point is tossed !
	ASSERT( GetConnectType() == CONNECT_CRYPT );
	ASSERT( !m_Crypt.IsInit());
	ASSERT( pEvent != nullptr );
	ASSERT( uiLen > 0 );

	// Try all client versions on the msg.
	if ( !m_Crypt.Init( m_net->m_seed, pEvent->m_Raw, uiLen, GetNetState()->isClientKR() ) )
	{
		DEBUG_MSG(( "%x:Odd login message length %u?\n", GetSocketID(), uiLen ));
#ifdef _DEBUG
		xRecordPacketData(this, pEvent->m_Raw, uiLen, "client->server");
#endif
		addLoginErr( PacketLoginError::BadEncLength );
		return false;
	}

	GetNetState()->detectAsyncMode();
	SetConnectType( m_Crypt.GetConnectType() );

	if ( !xCanEncLogin() )
	{
		addLoginErr((uchar)((m_Crypt.GetEncryptionType() == ENC_NONE? PacketLoginError::EncNoCrypt : PacketLoginError::EncCrypt) ));
		return false;
	}
	else if ( m_Crypt.GetConnectType() == CONNECT_LOGIN && !xCanEncLogin(true) )
	{
		addLoginErr( PacketLoginError::BadVersion );
		return false;
	}

    ASSERT(uiLen <= sizeof(CEvent));
    std::unique_ptr<CEvent> bincopy = std::make_unique<CEvent>();		// in buffer. (from client)
    memcpy(bincopy->m_Raw, pEvent->m_Raw, uiLen);
	if (!m_Crypt.Decrypt( pEvent->m_Raw, bincopy->m_Raw, MAX_BUFFER, uiLen ))
    {
        g_Log.EventError("NET-IN: xProcessClientSetup failed (Decrypt).\n");
        return false;
    }

    byte lErr = PacketLoginError::EncUnknown;
	tchar szAccount[MAX_ACCOUNT_NAME_SIZE+3];

	switch ( pEvent->Default.m_Cmd )
	{
		case XCMD_ServersReq:
		{
			if ( uiLen < sizeof( pEvent->ServersReq ))
				return false;

			lErr = Login_ServerList( pEvent->ServersReq.m_acctname, pEvent->ServersReq.m_acctpass );
			if ( lErr == PacketLoginError::Success )
			{
				Str_GetBare( szAccount, pEvent->ServersReq.m_acctname, sizeof(szAccount)-1 );
				CAccount * pAcc = g_Accounts.Account_Find( szAccount );
				if (pAcc)
				{
                    if (m_Crypt.GetClientVerNumber())
                        pAcc->m_TagDefs.SetNum("clientversion", m_Crypt.GetClientVerNumber());
					if (GetNetState()->getReportedVersion())
                        pAcc->m_TagDefs.SetNum("reportedcliver", GetNetState()->getReportedVersion());
                    else
                        new PacketClientVersionReq(this); // client version 0 ? ask for it.
				}
				else
				{
					// If i can't set the tag is better to stop login now
					lErr = PacketLoginError::Invalid;
				}
			}

			break;
		}

		case XCMD_CharListReq:
		{
			if ( uiLen < sizeof( pEvent->CharListReq ))
				return false;

			lErr = Setup_ListReq( pEvent->CharListReq.m_acctname, pEvent->CharListReq.m_acctpass, true );
			if ( lErr == PacketLoginError::Success )
			{
				// pass detected client version to the game server to make valid cliver used
				Str_GetBare( szAccount, pEvent->CharListReq.m_acctname, sizeof(szAccount)-1 );
				CAccount * pAcc = g_Accounts.Account_Find( szAccount );
				if (pAcc)
				{
					dword tmSid = 0x7f000001;
					dword tmVer = (dword)(pAcc->m_TagDefs.GetKeyNum("clientversion"));
					dword tmVerReported = (dword)(pAcc->m_TagDefs.GetKeyNum("reportedcliver"));
					pAcc->m_TagDefs.DeleteKey("clientversion");
					pAcc->m_TagDefs.DeleteKey("reportedcliver");

					if ( g_Cfg.m_fUseAuthID )
					{
						tmSid = (dword)(pAcc->m_TagDefs.GetKeyNum("customerid"));
						pAcc->m_TagDefs.DeleteKey("customerid");
					}

					DEBUG_MSG(("%x:xProcessClientSetup for %s, with AuthId %u and CliVersion %u / CliVersionReported %u\n", GetSocketID(), pAcc->GetName(), tmSid, tmVer, tmVerReported));

					if ( tmSid != 0 && tmSid == pEvent->CharListReq.m_Account )
					{
						// request client version if the client has not reported it to server yet
						if ( (tmVerReported == 0) && (tmVer > 1'26'04'00) )
                        {   // if we send this packet to clients < 1.26.04.00 we'll desynchronize the stream and break the login process
							new PacketClientVersionReq(this);
                        }

						if ( tmVerReported != 0 )
						{
							GetNetState()->m_reportedVersionNumber = tmVerReported;
						}
						else if ( tmVer != 0 )
						{
							m_Crypt.SetClientVerFromNumber(tmVer, false);
							GetNetState()->m_clientVersionNumber = tmVer;
						}

						// client version change may toggle async mode, it's important to flush pending data to the client before this happens
						GetNetState()->detectAsyncMode();

						if ( !xCanEncLogin(true) )
							lErr = PacketLoginError::BadVersion;
					}
					else
					{
						lErr = PacketLoginError::BadAuthID;
					}
				}
				else
				{
					lErr = PacketLoginError::Invalid;
				}
			}

			break;
		}

#ifdef _DEBUG
		default:
		{
			DEBUG_ERR(("Unknown/bad packet to receive at this time: 0x%X\n", pEvent->Default.m_Cmd));
		}
#endif
	}

	xRecordPacketData(this, pEvent->m_Raw, uiLen, "client->server");

	if ( lErr != PacketLoginError::Success )	// it never matched any crypt format.
	{
		addLoginErr( lErr );
	}

	return( lErr == PacketLoginError::Success );
}

bool CClient::xCanEncLogin(bool bCheckCliver)
{
	ADDTOCALLSTACK("CClient::xCanEncLogin");
	if ( !bCheckCliver )
	{
		if ( m_Crypt.GetEncryptionType() == ENC_NONE )
			return ( g_Cfg.m_fUsenocrypt ); // Server don't want no-crypt clients

		return ( g_Cfg.m_fUsecrypt ); // Server don't want crypt clients
	}
	else
	{
		if ( !g_Serv.m_ClientVersion.GetClientVerNumber() ) // Any Client allowed
			return true;

		if ( m_Crypt.GetEncryptionType() != ENC_NONE )
			return ( m_Crypt.GetClientVerNumber() == g_Serv.m_ClientVersion.GetClientVerNumber() );
		else
			return true;	// if unencrypted we check that later
	}
}
