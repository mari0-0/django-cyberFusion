from django.shortcuts import render
from django.http import JsonResponse
import subprocess


def run_python_script(request):
  try:
    subprocess.check_output(['python', 'project.py', '-d', 'vvitguntur.com', '--all'], text=True)
  
    with open(f'outputs/vvitguntur.com.txt', 'r') as file:
      result = file.read()
    return JsonResponse({'result': result})
  
  except FileNotFoundError:
    return JsonResponse({'error': 'File not found'}, status=404)
  
  except Exception as e:
    return JsonResponse({'error': str(e)}, status=500)