package main

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	usersCollection = "users"
	rulesCollection = "rules"
)

type dbUser struct {
	Username  string     `bson:"username" json:"username"`
	Password  string     `bson:"password" json:"password"`
	Rule      string     `bson:"rule" json:"rule"`
	Enabled   *bool      `bson:"enabled,omitempty" json:"enabled,omitempty"`
	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	UpdatedAt time.Time  `bson:"updated_at" json:"updated_at"`
}

type dbRule struct {
	Name      string    `bson:"name" json:"name"`
	Content   string    `bson:"content" json:"content"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

type mongoStore struct {
	client *mongo.Client
	db     *mongo.Database
}

func newMongoStore(ctx context.Context, uri, dbName string) (*mongoStore, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	store := &mongoStore{
		client: client,
		db:     client.Database(dbName),
	}
	if err := store.ensureIndexes(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *mongoStore) ensureIndexes(ctx context.Context) error {
	users := s.db.Collection(usersCollection)
	rules := s.db.Collection(rulesCollection)

	_, err := users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return err
	}

	_, err = rules.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	return err
}

func (s *mongoStore) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

func (s *mongoStore) Users(ctx context.Context) ([]dbUser, error) {
	cur, err := s.db.Collection(usersCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbUser
	for cur.Next(ctx) {
		var u dbUser
		if err := cur.Decode(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, cur.Err()
}

func (s *mongoStore) UpsertUser(ctx context.Context, u dbUser) error {
	u.UpdatedAt = time.Now()
	enabled := true
	if u.Enabled != nil {
		enabled = *u.Enabled
	}
	update := bson.M{
		"$set": bson.M{
			"username":   u.Username,
			"password":   u.Password,
			"rule":       u.Rule,
			"enabled":    enabled,
			"updated_at": u.UpdatedAt,
		},
	}
	if u.ExpiresAt != nil && !u.ExpiresAt.IsZero() {
		update["$set"].(bson.M)["expires_at"] = *u.ExpiresAt
	} else {
		update["$unset"] = bson.M{"expires_at": ""}
	}
	_, err := s.db.Collection(usersCollection).UpdateOne(ctx, bson.M{"username": u.Username}, update, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) DeleteUser(ctx context.Context, username string) error {
	_, err := s.db.Collection(usersCollection).DeleteOne(ctx, bson.M{"username": username})
	return err
}

func (s *mongoStore) Rules(ctx context.Context) ([]dbRule, error) {
	cur, err := s.db.Collection(rulesCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []dbRule
	for cur.Next(ctx) {
		var r dbRule
		if err := cur.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, cur.Err()
}

func (s *mongoStore) GetRule(ctx context.Context, name string) (*dbRule, error) {
	var r dbRule
	err := s.db.Collection(rulesCollection).FindOne(ctx, bson.M{"name": name}).Decode(&r)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("rule not found")
	}
	return &r, err
}

func (s *mongoStore) UpsertRule(ctx context.Context, r dbRule) error {
	r.UpdatedAt = time.Now()
	update := bson.M{
		"$set": bson.M{
			"name":       r.Name,
			"content":    r.Content,
			"updated_at": r.UpdatedAt,
		},
	}
	_, err := s.db.Collection(rulesCollection).UpdateOne(ctx, bson.M{"name": r.Name}, update, options.Update().SetUpsert(true))
	return err
}

func (s *mongoStore) DeleteRule(ctx context.Context, name string) error {
	_, err := s.db.Collection(rulesCollection).DeleteOne(ctx, bson.M{"name": name})
	return err
}
