#include <windows.h>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

int main() {
    HRESULT hres;

    // Initialize COM library
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code: " << hres << std::endl;
        return 1;
    }

    // Initialize COM security
    hres = CoInitializeSecurity(
        nullptr,
        -1,                          // Default authentication service
        nullptr,                     // Default authorization service
        nullptr,                     // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,    // Default authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Default impersonation level
        nullptr,                     // Default authentication settings
        EOAC_NONE,                   // Additional capabilities
        nullptr                      // Reserved
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM security. Error code: " << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Create a WMI COM instance
    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code: " << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Connect to the WMI service
    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Namespace
        nullptr,                // User name
        nullptr,                // User password
        0,                      // Locale
        nullptr,                // Security flags
        0,                      // Authority
        0,                      // Context
        &pSvc                   // IWbemServices proxy
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to connect to WMI service. Error code: " << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Set the security levels
    hres = CoSetProxyBlanket(
        pSvc,                        // IWbemServices proxy
        RPC_C_AUTHN_WINNT,           // Authentication method
        RPC_C_AUTHZ_NONE,            // Authorization method
        nullptr,                     // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // Authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation level
        nullptr,                     // Client identity
        EOAC_NONE                    // Additional capabilities
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to set proxy blanket. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Query USB devices using WMI
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'USB'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hres)) {
        std::cerr << "Query for USB devices failed. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Enumerate and display USB device details
    IWbemClassObject* pclsObj = nullptr;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;

        // Get the device description
        hres = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            wprintf(L"Description: %s\n", vtProp.bstrVal);
            VariantClear(&vtProp);
        }

        // Get the device hardware ID (includes bus ID)
        hres = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            wprintf(L"Hardware ID: %s\n", vtProp.bstrVal);
            VariantClear(&vtProp);
        }

        pclsObj->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return 0;
}
