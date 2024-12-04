import { NextFunction, Request, Response } from "express";

type AsynControllerType = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<any>;

/**
 *
 * @param controller Handlle catching of errors and send to the error handler
 * without always using trycatch in every controller
 * @returns
 */
export const asyncHandler =
  (controller: AsynControllerType): AsynControllerType =>
  async (req, res, next) => {
    try {
      await controller(req, res, next);
    } catch (error) {
      next(error);
    }
  };
