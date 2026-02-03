#include "bits_sim.h"
#include "../logger/logger.h"
#include <iostream>

void BitsSimulator::RunAnalysis() {
    LOG_INFO("[BITS] Initializing Real-time BITS Analysis...");
    
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        LOG_ERROR("[BITS] CoInitializeEx failed.");
        return;
    }

    IBackgroundCopyManager* pManager = NULL;
    hr = CoCreateInstance(__uuidof(BackgroundCopyManager), NULL, CLSCTX_LOCAL_SERVER,
                          __uuidof(IBackgroundCopyManager), (void**)&pManager);

    if (SUCCEEDED(hr)) {
        LOG_SUCCESS("[BITS] Connected to BITS Service.");
        
        IEnumBackgroundCopyJobs* pEnum = NULL;
        hr = pManager->EnumJobs(0, &pEnum); // 0 = all users if admin, but here current user
        
        if (SUCCEEDED(hr)) {
            IBackgroundCopyJob* pJob = NULL;
            ULONG fetched = 0;
            int jobCount = 0;

            while (pEnum->Next(1, &pJob, &fetched) == S_OK) {
                jobCount++;
                LPWSTR pName = NULL;
                pJob->GetDisplayName(&pName);
                
                std::wstring ws(pName);
                std::string name(ws.begin(), ws.end());
                LOG_TRACE("[BITS] Found Active Job: " + name);
                
                CoTaskMemFree(pName);
                pJob->Release();
            }
            
            if (jobCount == 0) {
                LOG_INFO("[BITS] No active BITS jobs found.");
            } else {
                LOG_SUCCESS("[BITS] Enumerated " + std::to_string(jobCount) + " jobs.");
            }
            pEnum->Release();
        }
        pManager->Release();
    } else {
        LOG_ERROR("[BITS] Failed to connect to BITS service. Check permissions.");
    }

    CoUninitialize();
}
