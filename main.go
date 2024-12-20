package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "rolo",
		Usage: "Manage and inspect roles and their table permissions in PostgreSQL",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "dsn",
				Usage:    "PostgreSQL DSN (e.g. postgres://user:pass@localhost:5432/mydb?sslmode=disable)",
				EnvVars:  []string{"ROLO_DSN"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Usage:   "Filter results, e.g. 'role=rolename' or 'table=tablename'",
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "grant",
				Usage:     "Grant permissions to a role on a table",
				ArgsUsage: "[role]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "permissions",
						Aliases:  []string{"p"},
						Usage:    "Comma-separated list of permissions to grant (e.g. SELECT,INSERT)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "table",
						Aliases:  []string{"t"},
						Usage:    "Name of the table to grant permissions on",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					if c.Args().Len() < 1 {
						return cli.Exit("Please provide a role to grant permissions to.", 1)
					}
					role := c.Args().Get(0)
					dsn := c.String("dsn")
					table := c.String("table")
					perms := c.String("permissions")

					return grantPermissions(dsn, role, table, perms)
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke permissions from a role on a table",
				ArgsUsage: "[role]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "permissions",
						Aliases:  []string{"p"},
						Usage:    "Comma-separated list of permissions to revoke (e.g. SELECT,INSERT)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "table",
						Aliases:  []string{"t"},
						Usage:    "Name of the table to revoke permissions from",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					if c.Args().Len() < 1 {
						return cli.Exit("Please provide a role to revoke permissions from.", 1)
					}
					role := c.Args().Get(0)
					dsn := c.String("dsn")
					table := c.String("table")
					perms := c.String("permissions")

					return revokePermissions(dsn, role, table, perms)
				},
			},
			{
				Name:    "list",
				Usage:   "List roles and their permissions",
				Aliases: []string{"ls"},
				Action:  listRoles,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func listRoles(c *cli.Context) error {
	dsn := c.String("dsn")
	filterStr := c.String("filter")

	var roleFilter, tableFilter string
	if filterStr != "" {
		// Parse the filter
		// Expected formats: "role=someRole" or "table=someTable"
		parts := strings.SplitN(filterStr, "=", 2)
		if len(parts) == 2 {
			key, val := parts[0], parts[1]
			switch key {
			case "role":
				roleFilter = val
			case "table":
				tableFilter = val
			default:
				return cli.Exit("Invalid filter format. Use 'role=NAME' or 'table=NAME'.", 1)
			}
		} else {
			return cli.Exit("Invalid filter format. Use 'role=NAME' or 'table=NAME'.", 1)
		}
	}

	return showRolesAndPermissions(dsn, roleFilter, tableFilter)
}

func listDatabases(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Println("Databases:")
	for rows.Next() {
		var datname string
		if err := rows.Scan(&datname); err != nil {
			return err
		}
		fmt.Printf(" - %s\n", datname)
	}
	return rows.Err()
}

func showRolesAndPermissions(dsn, roleFilter, tableFilter string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	roles, err := getAllRoles(db)
	if err != nil {
		return err
	}
	tables, err := getAllTables(db)
	if err != nil {
		return err
	}

	// Extract the database name from the DSN for display only
	dbName := extractDBName(dsn)
	fmt.Printf("Permissions in database %s:\n\n", dbName)
	fmt.Printf("%-20s %-20s %-50s\n", "Role", "Table", "Permissions")
	fmt.Println(strings.Repeat("-", 95))

	for _, role := range roles {
		// Apply role filter if provided
		if roleFilter != "" && role != roleFilter {
			continue
		}

		for _, table := range tables {
			// Apply table filter if provided
			if tableFilter != "" && table != tableFilter {
				continue
			}

			perms, err := getTablePermissionsForRole(db, table, role)
			if err != nil {
				return err
			}
			if perms == "" {
				perms = "<no access>"
			}
			fmt.Printf("%-20s %-20s %-50s\n", role, table, perms)
		}
	}

	return nil
}

func getAllRoles(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT rolname FROM pg_roles ORDER BY rolname;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		// Ignore roles that start with pg_
		if strings.HasPrefix(role, "pg_") {
			continue
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func getAllTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT tablename 
                           FROM pg_catalog.pg_tables 
                           WHERE schemaname NOT IN ('pg_catalog', 'information_schema');`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tables = append(tables, t)
	}
	return tables, rows.Err()
}

func getTablePermissionsForRole(db *sql.DB, table, role string) (string, error) {
	privileges := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
	var granted []string

	for _, priv := range privileges {
		query := fmt.Sprintf("SELECT has_table_privilege($1, $2, '%s')", priv)
		var has bool
		if err := db.QueryRow(query, role, table).Scan(&has); err != nil {
			return "", err
		}
		if has {
			granted = append(granted, priv)
		}
	}

	return strings.Join(granted, ", "), nil
}

func grantPermissions(dsn, role, table, perms string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// Split permissions by comma
	permsList := strings.Split(perms, ",")
	for i := range permsList {
		permsList[i] = strings.TrimSpace(permsList[i])
	}

	// Construct a GRANT statement
	grantSQL := fmt.Sprintf(`GRANT %s ON "%s" TO "%s";`, strings.Join(permsList, ", "), table, role)

	_, err = db.Exec(grantSQL)
	if err != nil {
		return fmt.Errorf("failed to grant permissions: %w", err)
	}

	fmt.Printf("Granted %s on %s to %s\n", strings.Join(permsList, ", "), table, role)
	return nil
}

func revokePermissions(dsn, role, table, perms string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	// Split permissions by comma
	permsList := strings.Split(perms, ",")
	for i := range permsList {
		permsList[i] = strings.TrimSpace(permsList[i])
	}

	// Construct a REVOKE statement
	revokeSQL := fmt.Sprintf(`REVOKE %s ON "%s" FROM "%s";`, strings.Join(permsList, ", "), table, role)

	_, err = db.Exec(revokeSQL)
	if err != nil {
		return fmt.Errorf("failed to revoke permissions: %w", err)
	}

	fmt.Printf("Revoked %s on %s from %s\n", strings.Join(permsList, ", "), table, role)
	return nil
}

func extractDBName(dsn string) string {
	// A simple approach to extract the database name from DSN:
	// Assuming DSN looks like: postgres://user:pass@host:port/dbname?params
	// We'll split by '/' and then take the last part before '?'.
	parts := strings.SplitN(dsn, "?", 2)
	base := parts[0]
	segments := strings.Split(base, "/")
	if len(segments) > 3 {
		return segments[len(segments)-1]
	}
	return "<unknown>"
}
