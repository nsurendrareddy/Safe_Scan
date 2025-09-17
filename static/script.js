let dangerChart = null;

// Enhanced tab switching with smooth transitions
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('show'));
    btn.classList.add('active');
    
    // Smooth transition for tab content
    setTimeout(() => {
      document.getElementById(btn.dataset.tab).classList.add('show');
    }, 100);
  });
});

function getRiskColor(pct) {
  if (pct < 30) return 'rgba(0,200,0,0.95)';
  if (pct < 70) return 'rgba(255,165,0,0.95)';
  return 'rgba(255,0,0,0.95)';
}

function setStats(data) {
  const map = {
    total: 'statsTotal',
    malicious: 'statsMalicious',
    suspicious: 'statsSuspicious',
    harmless: 'statsHarmless',
    undetected: 'statsUndetected',
    timeout: 'statsTimeout'
  };
  
  Object.entries(map).forEach(([key, id], index) => {
    const el = document.getElementById(id);
    if (el && key in data) {
      el.textContent = key.charAt(0).toUpperCase() + key.slice(1) + ': ' + data[key];
      
      // Animate pills with stagger effect
      setTimeout(() => {
        el.classList.add('animate');
      }, index * 100);
    }
  });
}

function animateChart(ctx, pct) {
  // Create animated chart with smooth progression
  let currentPct = 0;
  const targetPct = pct;
  const duration = 1500; // 1.5 seconds
  const startTime = Date.now();
  
  function updateChart() {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Easing function for smooth animation
    const easeOutQuart = 1 - Math.pow(1 - progress, 4);
    currentPct = targetPct * easeOutQuart;
    
    if (dangerChart) dangerChart.destroy();
    
    dangerChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [currentPct, 100 - currentPct],
          backgroundColor: [getRiskColor(currentPct), 'rgba(34,34,34,0.9)'],
          borderWidth: 0
        }]
      },
      options: {
        cutout: '70%',
        plugins: {
          legend: { display: false }
        },
        animation: {
          duration: 0 // Disable default animation since we're doing custom
        }
      }
    });
    
    // Update percentage display
    document.getElementById('dangerValue').innerText = Math.round(currentPct) + '%';
    
    if (progress < 1) {
      requestAnimationFrame(updateChart);
    } else {
      // Final update with exact value
      document.getElementById('dangerValue').innerText = targetPct + '%';
    }
  }
  
  updateChart();
}

function updateResults(data) {
  const resultBox = document.getElementById('resultBox');
  const gaugeWrap = document.querySelector('.gauge-wrap');
  const dangerText = document.getElementById('dangerText');
  
  // Show results with smooth transition
  resultBox.classList.remove('hidden');
  
  // Trigger smooth reveal animation
  setTimeout(() => {
    resultBox.classList.add('show-results');
  }, 50);
  
  // Animate gauge appearance
  setTimeout(() => {
    gaugeWrap.classList.add('animate');
  }, 300);
  
  const pct = Math.max(0, Math.min(100, Number(data.danger_percentage || 0)));
  const ctx = document.getElementById('dangerMeter').getContext('2d');
  
  // Start chart animation after gauge appears
  setTimeout(() => {
    animateChart(ctx, pct);
  }, 600);
  
  // Animate status text
  setTimeout(() => {
    dangerText.classList.add('animate');
    
    if (pct < 30) {
      dangerText.innerText = '🟢 Safe';
      dangerText.style.color = '#00ff80';
    } else if (pct < 70) {
      dangerText.innerText = '🟡 Suspicious';
      dangerText.style.color = '#ffaa00';
    } else {
      dangerText.innerText = '🔴 Dangerous';
      dangerText.style.color = '#ff4444';
    }
  }, 900);
  
  // Reset pill animations
  document.querySelectorAll('.stats .pill').forEach(pill => {
    pill.classList.remove('animate');
  });
  
  // Animate stats with delay
  setTimeout(() => {
    setStats(data);
  }, 1200);
}

function showLoading() {
  const loading = document.getElementById('loading');
  loading.classList.remove('hidden');
  setTimeout(() => {
    loading.classList.add('show');
  }, 50);
}

function hideLoading() {
  const loading = document.getElementById('loading');
  loading.classList.remove('show');
  setTimeout(() => {
    loading.classList.add('hidden');
  }, 300);
}

function hideResults() {
  const resultBox = document.getElementById('resultBox');
  const gaugeWrap = document.querySelector('.gauge-wrap');
  const dangerText = document.getElementById('dangerText');
  
  // Reset all animations
  resultBox.classList.remove('show-results');
  gaugeWrap.classList.remove('animate');
  dangerText.classList.remove('animate');
  
  document.querySelectorAll('.stats .pill').forEach(pill => {
    pill.classList.remove('animate');
  });
  
  setTimeout(() => {
    resultBox.classList.add('hidden');
  }, 300);
}

async function scanURL() {
  const url = document.getElementById('urlInput').value.trim();
  const urlInput = document.getElementById('urlInput');
  
  if (!url) {
    // Shake animation for empty input
    urlInput.style.animation = 'shake 0.5s ease-in-out';
    setTimeout(() => {
      urlInput.style.animation = '';
    }, 500);
    return alert('Enter a URL');
  }
  
  // Add success pulse to input
  urlInput.style.boxShadow = '0 0 20px rgba(0, 255, 128, 0.5)';
  setTimeout(() => {
    urlInput.style.boxShadow = '';
  }, 500);
  
  hideResults();
  setTimeout(() => {
    showLoading();
  }, 300);
  
  try {
    const resp = await fetch('http://127.0.0.1:5000/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const data = await resp.json();
    
    setTimeout(() => {
      hideLoading();
      if (!resp.ok) throw new Error(data.error || 'Scan failed');
      
      setTimeout(() => {
        updateResults(data);
      }, 400);
    }, 1000); // Minimum loading time for better UX
    
  } catch (e) {
    hideLoading();
    
    // Error shake animation
    urlInput.style.animation = 'shake 0.5s ease-in-out';
    urlInput.style.borderColor = '#ff4444';
    
    setTimeout(() => {
      urlInput.style.animation = '';
      urlInput.style.borderColor = '';
    }, 500);
    
    alert('Error: ' + e.message);
  }
}

async function scanFile() {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  
  if (!file) {
    // Shake animation for no file selected
    fileInput.parentElement.style.animation = 'shake 0.5s ease-in-out';
    setTimeout(() => {
      fileInput.parentElement.style.animation = '';
    }, 500);
    return alert('Choose a file');
  }
  
  // Success pulse effect
  fileInput.parentElement.style.boxShadow = '0 0 20px rgba(0, 255, 128, 0.3)';
  setTimeout(() => {
    fileInput.parentElement.style.boxShadow = '';
  }, 500);
  
  const form = new FormData();
  form.append('file', file);
  
  hideResults();
  setTimeout(() => {
    showLoading();
  }, 300);
  
  try {
    const resp = await fetch('http://127.0.0.1:5000/scan_file', {
      method: 'POST',
      body: form
    });
    
    const data = await resp.json();
    
    setTimeout(() => {
      hideLoading();
      if (!resp.ok) throw new Error(data.error || 'File scan failed');
      
      setTimeout(() => {
        updateResults(data);
      }, 400);
    }, 1000); // Minimum loading time for better UX
    
  } catch (e) {
    hideLoading();
    
    // Error shake animation
    fileInput.parentElement.style.animation = 'shake 0.5s ease-in-out';
    fileInput.parentElement.style.borderColor = '#ff4444';
    
    setTimeout(() => {
      fileInput.parentElement.style.animation = '';
      fileInput.parentElement.style.borderColor = '';
    }, 500);
    
    alert('Error: ' + e.message);
  }
}

// Add shake keyframes dynamically
const shakeKeyframes = `
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
    20%, 40%, 60%, 80% { transform: translateX(5px); }
  }
`;

// Inject shake animation CSS
const style = document.createElement('style');
style.textContent = shakeKeyframes;
document.head.appendChild(style);

document.getElementById('scanBtn').addEventListener('click', scanURL);
document.getElementById('fileScanBtn').addEventListener('click', scanFile);

// Add hover effects to input fields
document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('urlInput');
  
  urlInput.addEventListener('input', (e) => {
    if (e.target.value.length > 0) {
      e.target.style.transform = 'scale(1.01)';
    } else {
      e.target.style.transform = 'scale(1)';
    }
  });
});