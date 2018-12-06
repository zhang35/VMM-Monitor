#include "mydriver.h"
#include <winsvc.h>
#include <conio.h>
#include <QString>

//װ��NT��������
bool LoadNTDriver(const WCHAR* lpszDriverName, const WCHAR* lpszDriverPath)
{
        WCHAR szDriverImagePath[256];
        //�õ�����������·��
        GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

        BOOL bRet = FALSE;
        QString info = "";
        SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
        SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����

        //�򿪷�����ƹ�����
        hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

        if( hServiceMgr == NULL )
        {
                //OpenSCManagerʧ��
                info = "OpenSCManager() Faild";
                bRet = FALSE;
                goto BeforeLeave;
        }
        else
        {
                ////OpenSCManager�ɹ�
                info = "OpenSCManager() ok !";
        }

        //������������Ӧ�ķ���
        hServiceDDK = CreateService( hServiceMgr,
                lpszDriverName, //�����������ע����е�����
                lpszDriverName, // ע������������ DisplayName ֵ
                SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��
                SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������
                SERVICE_DEMAND_START, // ע������������ Start ֵ
                SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ
                szDriverImagePath, // ע������������ ImagePath ֵ
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);

        DWORD dwRtn;
        //�жϷ����Ƿ�ʧ��
        if( hServiceDDK == NULL )
        {
                dwRtn = GetLastError();
                if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )
                {
                        //��������ԭ�򴴽�����ʧ��
                        info = "CrateService() Faild!";
                        bRet = FALSE;
                        goto BeforeLeave;
                }
                else
                {
                        //���񴴽�ʧ�ܣ������ڷ����Ѿ�������
                        info = "CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS!";
                }

                // ���������Ѿ����أ�ֻ��Ҫ��
                hServiceDDK = OpenService( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );
                if( hServiceDDK == NULL )
                {
                        //����򿪷���Ҳʧ�ܣ�����ζ����
                        dwRtn = GetLastError();
                        info = "OpenService() Faild !";
                        bRet = FALSE;
                        goto BeforeLeave;
                }
                else
                {
                        info = "OpenService() ok !";
                }
        }
        else
        {
                info = "CrateService() ok !";
        }

        //�����������
        bRet= StartService( hServiceDDK, NULL, NULL );
        if( !bRet )
        {
                DWORD dwRtn = GetLastError();
                if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING )
                {
                        info = "StartService() Faild!";
                        bRet = FALSE;
                        goto BeforeLeave;
                }
                else
                {
                        if( dwRtn == ERROR_IO_PENDING )
                        {
                                //�豸����ס
                                info = "StartService() Faild ERROR_IO_PENDING !";
                                bRet = FALSE;
                                goto BeforeLeave;
                        }
                        else
                        {
                                //�����Ѿ�����
                                info = "StartService() Faild ERROR_SERVICE_ALREADY_RUNNING !";
                                bRet = TRUE;
                                goto BeforeLeave;
                        }
                }
        }
        bRet = TRUE;
        info = "�������سɹ�";
//�뿪ǰ�رվ��
BeforeLeave:
        if(hServiceDDK)
        {
                CloseServiceHandle(hServiceDDK);
        }
        if(hServiceMgr)
        {
                CloseServiceHandle(hServiceMgr);
        }
        return bRet;
}



//ж����������
bool UnloadNTDriver(const WCHAR*  szSvrName )
{
        BOOL bRet = FALSE;
        QString info = "";
        SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
        SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����
        SERVICE_STATUS SvrSta;
        //��SCM������
        hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
        if( hServiceMgr == NULL )
        {
                //����SCM������ʧ��
                info = "OpenSCManager() Faild !";
                bRet = FALSE;
                goto BeforeLeave;
        }
        else
        {
                //����SCM������ʧ�ܳɹ�
                info = "OpenSCManager() ok !";
        }
        //����������Ӧ�ķ���
        hServiceDDK = OpenService( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );

        if( hServiceDDK == NULL )
        {
                //����������Ӧ�ķ���ʧ��
                info = "OpenService() Faild!";
                bRet = FALSE;
                goto BeforeLeave;
        }
        else
        {
                info = "OpenService() ok !";
        }
        //ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�
        if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )
        {
                info = "ControlService() Faild!";
        }
        else
        {
                //����������Ӧ��ʧ��
                info = "ControlService() ok !";
        }
        //��̬ж����������
        if( !DeleteService( hServiceDDK ) )
        {
                //ж��ʧ��
                info = "DeleteSrevice() Faild!";
        }
        else
        {
                //ж�سɹ�
                info = "����ж�سɹ�!";
        }
        bRet = TRUE;
BeforeLeave:
//�뿪ǰ�رմ򿪵ľ��
        if(hServiceDDK)
        {
                CloseServiceHandle(hServiceDDK);
        }
        if(hServiceMgr)
        {
                CloseServiceHandle(hServiceMgr);
        }
        return bRet;
}
