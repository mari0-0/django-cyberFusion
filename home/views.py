from django.shortcuts import render
from django.http import JsonResponse
import os
from django.conf import settings
import subprocess


def run_python_script(request):
  try:
    base_dir = settings.BASE_DIR
    project_script_path = os.path.join(base_dir, 'project.py')
    subprocess.check_output(['python', project_script_path, '-d', 'vvitguntur.com', '--all'], text=True)

  
    with open(f'{base_dir}/outputs/vvitguntur.com.txt', 'r') as file:
      result = file.read()
    return JsonResponse({'result': result})
  
  except FileNotFoundError:
    return JsonResponse({'error': 'File not found'}, status=404)
  
  except Exception as e:
    return JsonResponse({'error': str(e)}, status=500)