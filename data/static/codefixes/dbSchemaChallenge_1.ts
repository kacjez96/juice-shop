export function searchProducts() {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    
    // Opcja 1: Użycie parametryzowanego zapytania (bind parameters)
    models.sequelize.query(
      "SELECT * FROM Products WHERE ((name LIKE :searchTerm OR description LIKE :searchTerm) AND deletedAt IS NULL) ORDER BY name",
      {
        replacements: { searchTerm: `%${criteria}%` },
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