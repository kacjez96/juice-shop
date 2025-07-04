export function searchProductsAlt() {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    
    models.sequelize.query(
      `SELECT * FROM Products 
       WHERE ((name LIKE ? OR description LIKE ?) 
       AND deletedAt IS NULL) 
       ORDER BY name`,
      {
        replacements: [`%${criteria}%`, `%${criteria}%`],
        type: models.sequelize.QueryTypes.SELECT
      }
    )
    .then((products: any) => {
      const dataString = JSON.stringify(products)
      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name)
        products[i].description = req.__(products[i].description)
      }
      res.json(utils.queryResultToJson(products))
    })
    .catch((error: ErrorWithParent) => {
      next(error.parent)
    })
  }
}