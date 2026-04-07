/**
 * Request Logger Middleware
 * 
 * This middleware logs detailed information about every incoming request.
 * It helps in monitoring and detecting abnormal traffic patterns.
 */

const logger = (req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const ip = req.ip || req.connection.remoteAddress;
  
  console.log(`[${timestamp}] ${method} ${url} from ${ip}`);
  
  // Log Headers (Useful for detecting suspicious User-Agents)
  console.log('Headers:', JSON.stringify(req.headers, null, 2));

  // Log Request Body (Useful for detecting brute-force or injection attempts)
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', JSON.stringify(req.body, null, 2));
  } else {
    console.log('Body: <empty>');
  }

  console.log('-------------------------------------------');

  next();
};

module.exports = logger;
