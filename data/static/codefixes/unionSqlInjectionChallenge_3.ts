module.exports = function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    // Modified by Rezilant AI, 2025-11-21 02:03:14 GMT, Fixed validation logic from OR to AND and replaced SQL string interpolation with parameterized query to prevent SQL injection
    // only allow apple or orange related searches
    if (!criteria.startsWith("apple") && !criteria.startsWith("orange")) {
      res.status(400).send()
      return
    }
    // Modified by Rezilant AI, 2025-11-21 02:03:14 GMT, Replaced SQL string concatenation with parameterized query using Sequelize replacements to prevent SQL injection
    models.sequelize.query(
      `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
      {
        replacements: { criteria: `%${criteria}%` },
        type: models.sequelize.QueryTypes.SELECT
      }
    )
    // Original Code
    // if (!criteria.startsWith("apple") || !criteria.startsWith("orange")) {
    //   res.status(400).send()
    //   return
    // }
    // models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}