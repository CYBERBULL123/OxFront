module.exports = {
  apps: [
    {
      name: 'frontend',
      script: 'npm',
      args: 'start',
      env: {
        NODE_ENV: 'production',
      },
    },
    {
      name: 'backend',
      script: 'python',
      args: '-m uvicorn backend.app:app --host 0.0.0.0 --port 8000',
      env: {
        PYTHONPATH: '.',
      },
    },
  ],
};
