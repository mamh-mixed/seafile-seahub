import json
import os
from django.contrib import messages
from django.http import HttpResponseRedirect, FileResponse
from django.utils.translation import gettext as _
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from urllib.parse import quote

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.endpoints.utils import check_time_period_valid, export_logs_to_excel
from seahub.api2.permissions import IsProVersion
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.auth.decorators import login_required
from seahub.base.decorators import sys_staff_required
from seahub.utils import is_pro_version, query_export_status
from seahub.settings import SITE_ROOT


class SysLogsExport(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, IsProVersion)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        next_page = request.headers.get('referer', None)
        if not next_page:
            next_page = SITE_ROOT

        if not is_pro_version():
            messages.error(request, _('Failed to export excel, this feature is only in professional version.'))
            return HttpResponseRedirect(next_page)

        start = request.GET.get('start', None)
        end = request.GET.get('end', None)
        log_type = request.GET.get('logType', None)

        if not check_time_period_valid(start, end):
            messages.error(request, _('Failed to export excel, invalid start or end date'))
            return HttpResponseRedirect(next_page)

        task_id = export_logs_to_excel(start, end, log_type)
        res_data = {'task_id': task_id}
        return Response(res_data)


class FileLogsExportStatus(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, IsProVersion)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        """
        Get task status by task id
        :param request:
        :return:
        """
        task_id = request.GET.get('task_id', '')
        if not task_id:
            error_msg = 'task_id invalid.'
            return api_error(400, error_msg)
        resp = query_export_status(task_id)

        if resp.status_code == 500:
            logger.error('seafile io query status error: %s, %s' % (task_id, resp.text))
            return api_error(500, 'Internal Server Error')
        if not resp.status_code == 200:
            return api_error(resp.status_code, resp.content)

        is_finished = json.loads(resp.content)['is_finished']
        return Response({'is_finished': is_finished})


@login_required
@sys_staff_required
def sys_log_export_excel(request):
    task_id = request.GET.get('task_id', None)
    log_type = request.GET.get('log_type', None)
    
    if not task_id:
        error_msg = 'task_id invalid.'
        return api_error(400, error_msg)

    if log_type == 'loginadmin':
        excel_name = task_id + 'login-logs.xlsx'
    elif log_type == 'fileaudit':
        excel_name = task_id + 'file-access-logs.xlsx'
    elif log_type == 'fileupdate':
        excel_name = task_id + 'file-update-logs.xlsx'
    elif log_type == 'permaudit':
        excel_name = task_id + 'perm-audit-logs.xlsx'
    else:
        error_msg = 'log_type invalid'
        return api_error(400, error_msg)

    target_dir = '/tmp/seafile_events/'
    tmp_excel_path = os.path.join(target_dir, excel_name)
    if not os.path.isfile(tmp_excel_path):
        return api_error(400, excel_name + ' not found.')

    response = FileResponse(open(tmp_excel_path, 'rb'), content_type='application/ms-excel', as_attachment=True)
    os.remove(tmp_excel_path)
    response['Content-Disposition'] = 'attachment;filename*=UTF-8\'\'' + quote(excel_name)

    return response
