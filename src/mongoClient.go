package main

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

const databaseName = "auth"
const collectionName = "tokens"

var client mongo.Client
var ctx context.Context
var collection mongo.Collection

type MongoClient struct {
	MongoUrl string
}

type Token struct {
	Id           primitive.ObjectID `bson:"_id"`
	Guid         string
	RefreshToken string
	CreatedAt    int64
}

func (m *MongoClient) initClient() {
	var client, err = mongo.NewClient(options.Client().ApplyURI(m.MongoUrl))
	if err != nil {
		log.Fatal(err)
	}

	ctx, _ = context.WithTimeout(context.Background(), 10*time.Second)

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	collection = *client.Database(databaseName).Collection(collectionName)
}

func (m *MongoClient) persistToken(t Token) (err error) {
	_, err = collection.InsertOne(context.Background(), t)
	return err
}

func (m *MongoClient) getAllByGuid(guid string) (allByGuid []Token, err error) {
	cur, err := collection.Find(context.Background(), bson.M{"guid": guid})
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		result := Token{}
		err := cur.Decode(&result)
		if err != nil {
			log.Fatal(err)
		}
		allByGuid = append(allByGuid, result)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return allByGuid, err
}

func (m *MongoClient) getByGuidAndRefreshToken(guid string, refreshTokenPlainText string) (token Token, err error) {
	cur, err := collection.Find(context.Background(), bson.M{"guid": guid})
	if err != nil {
		log.Println(err)
		return Token{}, err
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		result := Token{}
		err := cur.Decode(&result)
		if err != nil {
			log.Println(err)
		} else {
			compareErr := bcrypt.CompareHashAndPassword([]byte(result.RefreshToken), []byte(refreshTokenPlainText))
			if compareErr == nil {
				return result, nil
			}
		}
	}
	if err := cur.Err(); err != nil {
		return Token{}, err
	}
	return Token{}, errors.New("No entity for guid " + guid + " and refreshToken " + refreshTokenPlainText)
}

func (m *MongoClient) removeOneRefreshToken(objectId primitive.ObjectID) (err error) {
	singleResult := collection.FindOneAndDelete(context.Background(), bson.M{"_id": objectId})
	return singleResult.Err()
}

func (m *MongoClient) removeAllRefreshTokenByGuid(guid string) (errList []error) {
	allByGuid, errGetAll := m.getAllByGuid(guid)
	if errGetAll != nil {
		return []error{errGetAll}
	}
	for _, token := range allByGuid {
		errRemove := m.removeOneRefreshToken(token.Id)
		if errRemove != nil {
			errList = append(errList, errRemove)
		}
	}
	return errList
}

func (m *MongoClient) closeConnection() {
	_ = client.Disconnect(context.Background())
}
