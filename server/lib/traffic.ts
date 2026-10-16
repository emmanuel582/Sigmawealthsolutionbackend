import type { Request, Response, NextFunction } from 'express';

export function concurrencyGuard(maxActive = 128) {
  let active=0;
  return (req: Request,res: Response,next: NextFunction) => {
    if(!req.path.startsWith('/api/'))return next();
    if(active>=maxActive){res.set('Retry-After','2');return res.status(503).json({message:'The service is busy. Please retry shortly.'});}
    active++;
    let released=false;
    const release=()=>{if(!released){released=true;active--;}};
    res.once('finish',release);res.once('close',release);
    next();
  };
}
