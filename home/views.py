from django.shortcuts import render
from django.http import JsonResponse
import os
from django.conf import settings
import subprocess


def run_python_script(request):
  try:
    base_dir = settings.BASE_DIR
    project_script_path = os.path.join(base_dir, 'project.py')
    domain = 'vvitguntur.com'
    subprocess.check_output(['py', project_script_path, '-d', domain, '--all'], text=True)

  
    with open(f'{base_dir}/outputs/{domain}.txt', 'r', encoding='utf8') as file:
      result = ''
      for line in file:
        result += line.strip() + '\n'
    return JsonResponse({'result': result})
  
  except FileNotFoundError:
    return JsonResponse({'error': 'File not found'}, status=404)
  
  except Exception as e:
    return JsonResponse({'error': str(e)}, status=500)
  
